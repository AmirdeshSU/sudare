//! HTTP handlers. Every handler that touches data takes a [`Session`], so only the
//! owner sees an analysis.

use crate::auth::{self, Session, now};
use crate::secrets::{self, constant_time_eq, random_token, sha256_hex};
use crate::{ApiError, AppState, ClientIp, MAX_INPUT_BYTES, Pending, UserMode};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Method, Uri, header};
use axum::response::{AppendHeaders, Html, IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Instant;
use sudare_core::{Action, EntityType, Prepared};
use sudare_egress::llm::{self, ApiKey, LlmError, LlmProvider, ProviderConfig, ProviderKind};
use sudare_egress::pipeline::{self, AnalyzeOptions};
use sudare_egress::ti::{TI_KEY_NAMES, TiRunner};

type ApiResult<T> = Result<T, ApiError>;

const LLM_KEY_NAMES: &[&str] = &["openai", "anthropic", "gemini", "openai-compatible"];
const PREVIEWS_PER_USER: usize = 20;

fn session_aad(user_id: i64, analysis_id: &str) -> Vec<u8> {
    format!("session:{user_id}:{analysis_id}").into_bytes()
}

fn key_aad(user_id: i64, name: &str) -> Vec<u8> {
    format!("key:{user_id}:{name}").into_bytes()
}

impl AppState {
    /// The user's saved key, else the server's environment key.
    fn api_key(&self, user_id: i64, name: &str) -> Option<ApiKey> {
        let saved = self
            .db
            .get_key(user_id, name)
            .ok()
            .flatten()
            .and_then(|blob| secrets::open(&self.cfg.secret_key, &key_aad(user_id, name), &blob))
            .and_then(|plain| String::from_utf8(plain).ok())
            .and_then(ApiKey::new);
        saved.or_else(|| {
            let env = match name {
                "openai" => "OPENAI_API_KEY".to_string(),
                "anthropic" => "ANTHROPIC_API_KEY".into(),
                "gemini" => "GEMINI_API_KEY".into(),
                "openai-compatible" => "SUDARE_OPENAI_COMPAT_KEY".into(),
                ti => format!("SUDARE_{}_KEY", ti.to_ascii_uppercase()),
            };
            ApiKey::from_env(&env)
        })
    }

    /// Base URLs come from server config only; users can't point the server at
    /// arbitrary hosts.
    fn provider(
        &self,
        user_id: i64,
        name: &str,
        model: Option<String>,
    ) -> ApiResult<Box<dyn LlmProvider>> {
        let kind = match name {
            "ollama" => ProviderKind::Ollama,
            "openai" => ProviderKind::OpenAi,
            "anthropic" => ProviderKind::Anthropic,
            "gemini" => ProviderKind::Gemini,
            "openai-compatible" => ProviderKind::OpenAiCompatible,
            other => {
                return Err(ApiError::new(
                    400,
                    "unknown_provider",
                    format!("unknown provider {other:?}"),
                ));
            }
        };
        let mut cfg = ProviderConfig::new(kind);
        cfg.api_key = self.api_key(user_id, kind.name());
        cfg.model = model;
        cfg.num_ctx = self.cfg.num_ctx;
        cfg.local_hosts = self.cfg.local_hosts.clone();
        match kind {
            ProviderKind::Ollama => cfg.base_url = self.cfg.ollama_url.clone(),
            ProviderKind::OpenAiCompatible => {
                cfg.base_url = self.cfg.compat_url.clone();
                cfg.model = cfg.model.or_else(|| self.cfg.compat_model.clone());
            }
            _ => {}
        }
        llm::build(cfg).map_err(|e| ApiError::new(400, "provider", e.to_string()))
    }

    fn open_session(&self, user_id: i64, id: &str, blob: &[u8]) -> ApiResult<Prepared> {
        let plain = secrets::open(&self.cfg.secret_key, &session_aad(user_id, id), blob)
            .ok_or_else(|| ApiError::new(500, "sealed", "stored session failed to decrypt"))?;
        Prepared::open(&plain, &self.cfg.secret_key)
            .map_err(|e| ApiError::new(500, "sealed", e.to_string()))
    }

    fn seal_session(&self, user_id: i64, id: &str, p: &Prepared) -> Vec<u8> {
        // Inner seal (core) then outer seal bound to user + analysis id.
        let inner = p.seal(&self.cfg.secret_key, secrets::random_bytes::<24>());
        secrets::seal(&self.cfg.secret_key, &session_aad(user_id, id), &inner)
    }
}

fn llm_error(e: LlmError) -> ApiError {
    match e {
        LlmError::Config(_) | LlmError::MissingKey(..) => {
            ApiError::new(400, "provider", e.to_string())
        }
        other => ApiError::new(502, "provider_failed", other.to_string()),
    }
}

/// A non-local provider needs the digest of exactly what will be sent.
fn require_confirmation(
    provider: &dyn LlmProvider,
    digest: &str,
    confirm: Option<&str>,
) -> ApiResult<()> {
    if provider.is_local() || confirm.is_some_and(|c| constant_time_eq(c, digest)) {
        return Ok(());
    }
    Err(ApiError::new(
        428,
        "confirmation_required",
        format!("{} is not local: review the masked text and send its digest as confirm_digest", provider.name()),
    )
    .with(json!({ "digest": digest, "provider": provider.name(), "base_url": provider.base_url().as_str() })))
}

/// The web UI (`web/dist`). Release builds embed it; debug builds read it from disk,
/// so `npm run watch` in `web/` is enough during development.
#[derive(rust_embed::Embed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
struct Ui;

const NO_UI: &str = "<!doctype html><meta charset=utf-8><title>Sudare</title>\
    <p>Sudare API is running, but this build has no web UI. Run <code>npm ci &amp;&amp; npm run wasm &amp;&amp; npm run build</code> in <code>web/</code> and rebuild, or use the CLI.</p>";

/// Static UI files for GET outside `/api`; JSON 404 for everything else.
pub async fn fallback(method: Method, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if !matches!(method, Method::GET | Method::HEAD) || path.starts_with("api/") {
        return not_found().await.into_response();
    }
    let path = if path.is_empty() { "index.html" } else { path };
    match Ui::get(path) {
        Some(f) => {
            // Vite fingerprints everything under assets/.
            let cache = if path.starts_with("assets/") {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            (
                [
                    (header::CONTENT_TYPE, f.metadata.mimetype().to_string()),
                    (header::CACHE_CONTROL, cache.to_string()),
                ],
                f.data,
            )
                .into_response()
        }
        None if path == "index.html" => Html(NO_UI).into_response(),
        None => not_found().await.into_response(),
    }
}

pub async fn not_found() -> ApiError {
    ApiError::new(404, "not_found", "no such endpoint")
}

/// Public: the login screen needs the mode before there is a session.
pub async fn health(State(s): State<AppState>) -> Json<Value> {
    let mode = if s.cfg.mode == UserMode::Single {
        "single"
    } else {
        "multi"
    };
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION"), "mode": mode }))
}

#[derive(Deserialize)]
pub struct LoginReq {
    token: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

pub async fn login(
    State(s): State<AppState>,
    axum::Extension(ClientIp(ip)): axum::Extension<ClientIp>,
    Json(r): Json<LoginReq>,
) -> ApiResult<Response> {
    let who = r.username.as_deref().unwrap_or("").to_ascii_lowercase();
    let throttle = format!("{ip}|{who}");
    let since = now() - auth::LOCKOUT_SECS;
    if s.db.recent_failures(&throttle, since)? >= auth::LOCKOUT_FAILURES {
        return Err(ApiError::new(
            429,
            "locked",
            "too many failed logins; try again in 15 minutes",
        ));
    }
    let user = match s.cfg.mode {
        UserMode::Single => {
            let ok = match (r.token.as_deref(), s.token_hash.as_deref()) {
                (Some(t), Some(h)) => constant_time_eq(&sha256_hex(t.as_bytes()), h),
                _ => false,
            };
            match (ok, s.local_user) {
                (true, Some(id)) => {
                    s.db.find_user("local")?
                        .map(|(u, _)| u)
                        .filter(|u| u.id == id)
                }
                _ => None,
            }
        }
        UserMode::Multi => {
            let pw = r.password.as_deref().unwrap_or("");
            match s.db.find_user(&who)? {
                Some((u, hash)) if auth::verify_password(pw, &hash) => Some(u),
                Some(_) => None,
                None => {
                    auth::verify_password(pw, &auth::DUMMY_HASH);
                    None
                }
            }
        }
    };
    let Some(user) = user else {
        s.db.record_failure(&throttle, now(), since)?;
        return Err(ApiError::new(401, "login_failed", "wrong credentials"));
    };
    s.db.clear_failures(&throttle)?;
    let (token, csrf) = (random_token(), random_token());
    s.db.create_session(
        &sha256_hex(token.as_bytes()),
        user.id,
        &csrf,
        now() + auth::SESSION_SECS,
    )?;
    let [a, b] = auth::session_cookies(&token, &csrf, s.cfg.cookie_secure);
    Ok((
        AppendHeaders([(header::SET_COOKIE, a), (header::SET_COOKIE, b)]),
        Json(json!({ "user": user, "csrf": csrf })),
    )
        .into_response())
}

pub async fn logout(State(s): State<AppState>, session: Session) -> ApiResult<Response> {
    s.db.delete_session(&session.token_hash)?;
    let [a, b] = auth::clear_cookies(s.cfg.cookie_secure);
    Ok((
        AppendHeaders([(header::SET_COOKIE, a), (header::SET_COOKIE, b)]),
        Json(json!({ "ok": true })),
    )
        .into_response())
}

pub async fn me(State(s): State<AppState>, session: Session) -> Json<Value> {
    let mode = if s.cfg.mode == UserMode::Single {
        "single"
    } else {
        "multi"
    };
    let connectors: Vec<&str> = s.cfg.fortisiem.iter().map(|_| "fortisiem").collect();
    Json(json!({ "user": session.user, "mode": mode, "connectors": connectors }))
}

#[derive(Deserialize)]
pub struct PullReq {
    incident_id: String,
}

/// Fetch an incident's triggering events. Returns unmasked text for the preview step;
/// nothing is stored or sent to a model here.
pub async fn pull_fortisiem(
    State(s): State<AppState>,
    _: Session,
    Json(r): Json<PullReq>,
) -> ApiResult<Json<Value>> {
    let f = s.cfg.fortisiem.as_ref().ok_or_else(|| {
        ApiError::new(
            404,
            "not_configured",
            "FortiSIEM is not configured on this server",
        )
    })?;
    let text = f
        .triggering_events(s.http.as_ref(), &r.incident_id)
        .await
        .map_err(|e| match e {
            sudare_egress::siem::SiemError::Config(m) => ApiError::new(400, "bad_request", m),
            other => ApiError::new(502, "siem_failed", other.to_string()),
        })?;
    if text.len() > MAX_INPUT_BYTES {
        return Err(ApiError::new(
            413,
            "too_large",
            "incident events are over 16 MiB",
        ));
    }
    Ok(Json(json!({ "text": text, "parser": "fortisiem" })))
}

pub async fn parsers(State(s): State<AppState>, _: Session) -> Json<Value> {
    let list: Vec<Value> = s
        .engine(false)
        .registry()
        .parsers()
        .map(|p| json!({ "name": p.name(), "description": p.description() }))
        .collect();
    Json(json!(list))
}

pub async fn providers(State(s): State<AppState>, session: Session) -> Json<Value> {
    let list: Vec<Value> = ["ollama", "openai", "anthropic", "gemini", "openai-compatible"]
        .iter()
        .map(|name| match s.provider(session.user.id, name, None) {
            Ok(p) => json!({ "name": name, "ready": true, "local": p.is_local(), "model": p.model(), "base_url": p.base_url().as_str() }),
            Err(e) => json!({ "name": name, "ready": false, "reason": e.message_text() }),
        })
        .collect();
    Json(json!(list))
}

impl ApiError {
    fn message_text(&self) -> String {
        self.message.clone()
    }
}

#[derive(Deserialize)]
pub struct PreviewReq {
    text: String,
    #[serde(default)]
    strict: bool,
    parser: Option<String>,
}

pub async fn preview(
    State(s): State<AppState>,
    session: Session,
    Json(r): Json<PreviewReq>,
) -> ApiResult<Json<Value>> {
    if r.text.len() > MAX_INPUT_BYTES {
        return Err(ApiError::new(413, "too_large", "input is over 16 MiB"));
    }
    let state = s.clone();
    let strict = r.strict;
    let prepared = tokio::task::spawn_blocking(move || {
        state
            .engine(strict)
            .prepare(&r.text, r.parser.as_deref(), secrets::random_bytes::<32>())
    })
    .await
    .map_err(|_| ApiError::new(500, "internal", "masking task failed"))?
    .map_err(|e| ApiError::new(400, "parser", e.to_string()))?;

    let digest = sha256_hex(prepared.input.text().as_bytes());
    let kept_domains: Vec<&str> = prepared
        .decisions
        .iter()
        .filter(|d| d.action == Action::Keep && d.entity.kind == EntityType::Fqdn)
        .map(|d| d.entity.normalized.as_str())
        .collect();
    let body = json!({
        "masked": prepared.input.text(),
        "digest": digest,
        "parser": prepared.parser,
        "lines": prepared.input.line_count(),
        "events": prepared.events,
        "parse_errors": prepared.parse_errors,
        "stats": prepared.stats,
        "public_indicators": prepared.indicators.len(),
        "kept_public_domains": kept_domains,
        "strict": strict,
    });
    let id = random_token()[..32].to_string();
    let mut previews = s.previews.lock().unwrap_or_else(|p| p.into_inner());
    let mine: Vec<(String, Instant)> = previews
        .iter()
        .filter(|(_, p)| p.user_id == session.user.id)
        .map(|(k, p)| (k.clone(), p.created))
        .collect();
    if mine.len() >= PREVIEWS_PER_USER
        && let Some((oldest, _)) = mine.iter().min_by_key(|(_, t)| *t)
    {
        previews.remove(oldest);
    }
    previews.insert(
        id.clone(),
        Pending {
            user_id: session.user.id,
            prepared,
            digest,
            strict,
            created: Instant::now(),
        },
    );
    let mut body = body;
    body["preview_id"] = json!(id);
    Ok(Json(body))
}

#[derive(Deserialize)]
pub struct RuleReq {
    name: String,
    #[serde(default)]
    condition: String,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
pub struct AnalyzeReq {
    preview_id: String,
    provider: String,
    model: Option<String>,
    confirm_digest: Option<String>,
    #[serde(default = "yes")]
    enrich: bool,
    rule: Option<RuleReq>,
}

pub async fn analyze(
    State(s): State<AppState>,
    session: Session,
    Json(r): Json<AnalyzeReq>,
) -> ApiResult<Json<Value>> {
    let uid = session.user.id;
    let provider = s.provider(uid, &r.provider, r.model.clone())?;
    let mut pending = {
        let mut previews = s.previews.lock().unwrap_or_else(|p| p.into_inner());
        match previews.get(&r.preview_id) {
            Some(p) if p.user_id == uid => {
                require_confirmation(provider.as_ref(), &p.digest, r.confirm_digest.as_deref())?;
                previews.remove(&r.preview_id).expect("present")
            }
            _ => {
                return Err(ApiError::new(
                    404,
                    "preview_not_found",
                    "preview expired or unknown; preview again",
                ));
            }
        }
    };

    let mut enrichment = vec![Vec::new(); pending.prepared.indicators.len()];
    if r.enrich && !pending.prepared.indicators.is_empty() {
        let mut runner = TiRunner::with_keys(|name| s.api_key(uid, name));
        if let Ok(cache) = sudare_egress::cache::Cache::open(
            &s.cfg.data_dir.join("ti-cache.sqlite"),
            std::time::Duration::from_secs(24 * 3600),
        ) {
            runner = runner.with_cache(cache);
        }
        enrichment = pipeline::enrich(&pending.prepared, &runner, s.http.as_ref()).await;
    }

    let opts = AnalyzeOptions {
        rule: r.rule.map(|x| (x.name, x.condition)),
        max_input_chars: None,
        now_unix: now() as u64,
    };
    let engine = s.engine(pending.strict);
    let result = match pipeline::analyze(
        engine,
        &mut pending.prepared,
        &enrichment,
        provider.as_ref(),
        s.http.as_ref(),
        &opts,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            // Keep the preview so the user can retry without re-uploading.
            let preview_id = r.preview_id.clone();
            pending.created = Instant::now();
            s.previews
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(preview_id, pending);
            return Err(llm_error(e));
        }
    };

    let id = random_token()[..32].to_string();
    let report = serde_json::to_value(&result.report)
        .map_err(|_| ApiError::new(500, "internal", "report"))?;
    let label = |v: &Value| v.as_str().map(str::to_string);
    let a = &report["analysis"];
    s.db.insert_analysis(
        &id,
        uid,
        now(),
        pending.prepared.input.text(),
        &result.masked_output,
        &report.to_string(),
        &s.seal_session(uid, &id, &pending.prepared),
        label(&a["verdict"]).as_deref(),
        label(&a["severity"]["level"]).as_deref(),
        label(&a["summary"]).as_deref(),
    )?;
    Ok(Json(json!({ "id": id, "report": report })))
}

pub async fn list(State(s): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    Ok(Json(json!(s.db.list_analyses(session.user.id)?)))
}

pub async fn get_analysis(
    State(s): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let uid = session.user.id;
    let row =
        s.db.get_analysis(uid, &id)?
            .ok_or_else(|| ApiError::new(404, "not_found", "no such analysis"))?;
    let prepared = s.open_session(uid, &row.id, &row.sealed_session)?;
    let chat: Vec<Value> = prepared
        .chat
        .iter()
        .map(|t| {
            json!({
                "question": prepared.map.unmask(t.question.as_str()).text,
                "answer": prepared.map.unmask(&t.answer).text,
            })
        })
        .collect();
    let report: Value = serde_json::from_str(&row.report).unwrap_or(Value::Null);
    Ok(Json(json!({
        "id": row.id,
        "created_at": row.created_at,
        "report": report,
        "masked_input": row.masked_input,
        "chat": chat,
    })))
}

pub async fn delete_analysis(
    State(s): State<AppState>,
    session: Session,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !s.db.delete_analysis(session.user.id, &id)? {
        return Err(ApiError::new(404, "not_found", "no such analysis"));
    }
    Ok(Json(json!({ "deleted": id })))
}

#[derive(Deserialize)]
pub struct ChatPreviewReq {
    question: String,
}

fn analysis_strict(report: &str) -> bool {
    serde_json::from_str::<Value>(report).is_ok_and(|v| v["meta"]["mode"] == "strict")
}

pub async fn chat_preview(
    State(s): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(r): Json<ChatPreviewReq>,
) -> ApiResult<Json<Value>> {
    let uid = session.user.id;
    let row =
        s.db.get_analysis(uid, &id)?
            .ok_or_else(|| ApiError::new(404, "not_found", "no such analysis"))?;
    let mut probe = s.open_session(uid, &id, &row.sealed_session)?;
    let masked = s
        .engine(analysis_strict(&row.report))
        .mask_followup(&mut probe, &r.question);
    Ok(Json(
        json!({ "masked_question": masked.as_str(), "digest": sha256_hex(masked.as_str().as_bytes()) }),
    ))
}

#[derive(Deserialize)]
pub struct ChatReq {
    question: String,
    provider: String,
    model: Option<String>,
    confirm_digest: Option<String>,
}

pub async fn chat(
    State(s): State<AppState>,
    session: Session,
    Path(id): Path<String>,
    Json(r): Json<ChatReq>,
) -> ApiResult<Json<Value>> {
    let uid = session.user.id;
    if r.question.trim().is_empty() || r.question.len() > 8 * 1024 {
        return Err(ApiError::new(
            400,
            "question",
            "question must be 1-8192 bytes",
        ));
    }
    let row =
        s.db.get_analysis(uid, &id)?
            .ok_or_else(|| ApiError::new(404, "not_found", "no such analysis"))?;
    let engine = s.engine(analysis_strict(&row.report));
    let provider = s.provider(uid, &r.provider, r.model)?;
    if !provider.is_local() {
        let mut probe = s.open_session(uid, &id, &row.sealed_session)?;
        let masked = engine.mask_followup(&mut probe, &r.question);
        require_confirmation(
            provider.as_ref(),
            &sha256_hex(masked.as_str().as_bytes()),
            r.confirm_digest.as_deref(),
        )?;
    }
    let mut prepared = s.open_session(uid, &id, &row.sealed_session)?;
    let mut history = std::mem::take(&mut prepared.chat);
    let answer = pipeline::chat(
        engine,
        &mut prepared,
        &row.masked_output,
        &mut history,
        &r.question,
        provider.as_ref(),
        s.http.as_ref(),
        None,
    )
    .await
    .map_err(llm_error)?;
    prepared.chat = history;
    s.db.update_session(uid, &id, &s.seal_session(uid, &id, &prepared))?;
    Ok(Json(json!({ "answer": answer })))
}

pub async fn list_keys(State(s): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    let saved = s.db.list_keys(session.user.id)?;
    let list: Vec<Value> = LLM_KEY_NAMES
        .iter()
        .map(|n| (n, "llm"))
        .chain(TI_KEY_NAMES.iter().map(|n| (n, "threat_intel")))
        .map(|(name, kind)| {
            let row = saved.iter().find(|(n, _, _)| n == name);
            json!({
                "name": name,
                "kind": kind,
                "saved": row.is_some(),
                "hint": row.map(|r| r.1.clone()),
                "updated_at": row.map(|r| r.2),
            })
        })
        .collect();
    Ok(Json(json!(list)))
}

#[derive(Deserialize)]
pub struct PutKeyReq {
    key: String,
}

pub async fn put_key(
    State(s): State<AppState>,
    session: Session,
    Path(name): Path<String>,
    Json(r): Json<PutKeyReq>,
) -> ApiResult<Json<Value>> {
    if !LLM_KEY_NAMES.contains(&name.as_str()) && !TI_KEY_NAMES.contains(&name.as_str()) {
        return Err(ApiError::new(
            400,
            "unknown_key",
            format!("unknown key name {name:?}"),
        ));
    }
    let key = zeroize::Zeroizing::new(r.key.trim().to_string());
    if key.len() < 8 || key.len() > 512 || key.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ApiError::new(
            400,
            "invalid_key",
            "key must be 8-512 printable characters",
        ));
    }
    let hint = if key.len() >= 12 {
        format!("…{}", &key[key.len() - 4..])
    } else {
        "saved".to_string()
    };
    let sealed = secrets::seal(
        &s.cfg.secret_key,
        &key_aad(session.user.id, &name),
        key.as_bytes(),
    );
    s.db.put_key(session.user.id, &name, &sealed, &hint, now())?;
    Ok(Json(json!({ "name": name, "saved": true, "hint": hint })))
}

pub async fn delete_key(
    State(s): State<AppState>,
    session: Session,
    Path(name): Path<String>,
) -> ApiResult<Json<Value>> {
    let removed = s.db.delete_key(session.user.id, &name)?;
    Ok(Json(json!({ "name": name, "removed": removed })))
}

fn multi_only(s: &AppState) -> ApiResult<()> {
    match s.cfg.mode {
        UserMode::Multi => Ok(()),
        UserMode::Single => Err(ApiError::new(
            404,
            "not_found",
            "user management needs SUDARE_MODE=multi",
        )),
    }
}

pub async fn list_users(State(s): State<AppState>, session: Session) -> ApiResult<Json<Value>> {
    multi_only(&s)?;
    session.require_admin()?;
    Ok(Json(json!(s.db.list_users()?)))
}

#[derive(Deserialize)]
pub struct CreateUserReq {
    username: String,
    password: String,
    #[serde(default)]
    admin: bool,
}

pub async fn create_user(
    State(s): State<AppState>,
    session: Session,
    Json(r): Json<CreateUserReq>,
) -> ApiResult<Json<Value>> {
    multi_only(&s)?;
    session.require_admin()?;
    let name = r.username.trim().to_ascii_lowercase();
    let valid = (3..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid {
        return Err(ApiError::new(
            400,
            "username",
            "username: 3-64 of a-z 0-9 . _ -",
        ));
    }
    crate::config::check_password(&r.password).map_err(|e| ApiError::new(400, "password", e))?;
    if s.db.find_user(&name)?.is_some() {
        return Err(ApiError::new(409, "exists", "username taken"));
    }
    let role = if r.admin { "admin" } else { "user" };
    let id =
        s.db.create_user(&name, &auth::hash_password(&r.password), role, now())?;
    Ok(Json(json!({ "id": id, "username": name, "role": role })))
}

pub async fn delete_user(
    State(s): State<AppState>,
    session: Session,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    multi_only(&s)?;
    session.require_admin()?;
    if id == session.user.id {
        return Err(ApiError::new(
            400,
            "self",
            "you can't delete your own account",
        ));
    }
    if !s.db.delete_user(id)? {
        return Err(ApiError::new(404, "not_found", "no such user"));
    }
    Ok(Json(json!({ "deleted": id })))
}

pub async fn get_settings(State(s): State<AppState>, _: Session) -> Json<Value> {
    Json(json!({ "retention_days": s.retention_days() }))
}

#[derive(Deserialize)]
pub struct SettingsReq {
    retention_days: u32,
}

pub async fn put_settings(
    State(s): State<AppState>,
    session: Session,
    Json(r): Json<SettingsReq>,
) -> ApiResult<Json<Value>> {
    session.require_admin()?;
    if !(1..=3650).contains(&r.retention_days) {
        return Err(ApiError::new(
            400,
            "retention",
            "retention_days must be 1-3650",
        ));
    }
    s.db.set_setting("retention_days", &r.retention_days.to_string())?;
    let removed = s.purge();
    Ok(Json(
        json!({ "retention_days": r.retention_days, "purged": removed }),
    ))
}
