//! Sudare HTTP API. Single-user by default (127.0.0.1, startup token); optional
//! multi-user mode with argon2 passwords. Cloud calls need the masked preview's
//! digest echoed back, so the server enforces the review step, not just the UI.
#![forbid(unsafe_code)]

pub mod api;
pub mod auth;
pub mod config;
pub mod db;
pub mod secrets;

pub use config::{Config, UserMode};

use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use db::Db;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sudare_core::{Engine, Policy, Prepared};
use sudare_egress::http::Http;
use zeroize::Zeroizing;

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
const PREVIEW_TTL: Duration = Duration::from_secs(30 * 60);

/// A masked preview waiting for the user's go-ahead. In memory only.
pub struct Pending {
    pub user_id: i64,
    pub prepared: Prepared,
    pub digest: String,
    pub strict: bool,
    pub created: Instant,
}

pub struct Inner {
    pub cfg: Config,
    pub db: Db,
    /// [default mode, strict mode]
    pub engines: [Engine; 2],
    pub http: Arc<dyn Http>,
    pub previews: Mutex<HashMap<String, Pending>>,
    /// Single-user mode: sha256 of the login token, and the local user's id.
    pub token_hash: Option<String>,
    pub local_user: Option<i64>,
}

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

impl std::ops::Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

#[derive(Clone)]
pub struct ClientIp(pub String);

impl AppState {
    /// Open storage, bootstrap users and build the engines. Returns the single-user
    /// login token when it was generated here (so it can be printed once).
    pub fn new(
        cfg: Config,
        http: Arc<dyn Http>,
    ) -> Result<(Self, Option<Zeroizing<String>>), String> {
        let db = Db::open(&cfg.data_dir.join("sudare.sqlite"))?;
        let policy = match &cfg.policy {
            Some(p) => Policy::load(p).map_err(|e| e.to_string())?,
            None => Policy::default(),
        };
        let engines = [
            Engine::new(policy.clone()).map_err(|e| e.to_string())?,
            Engine::new(policy.strict()).map_err(|e| e.to_string())?,
        ];
        let mut printed = None;
        let (token_hash, local_user) = match cfg.mode {
            UserMode::Single => {
                let id = match db.find_user("local").map_err(|e| e.to_string())? {
                    Some((u, _)) => u.id,
                    // "!" is not a valid PHC hash: the local user can't log in by password.
                    None => db
                        .create_user("local", "!", "admin", auth::now())
                        .map_err(|e| e.to_string())?,
                };
                let token = match &cfg.token {
                    Some(t) => t.clone(),
                    None => {
                        let t = Zeroizing::new(secrets::random_token());
                        printed = Some(t.clone());
                        t
                    }
                };
                (Some(secrets::sha256_hex(token.as_bytes())), Some(id))
            }
            UserMode::Multi => {
                if db.user_count().map_err(|e| e.to_string())? == 0 {
                    let pw = cfg.admin_password.as_ref().ok_or(
                        "no users yet: set SUDARE_ADMIN_PASSWORD to create the first admin",
                    )?;
                    config::check_password(pw)
                        .map_err(|e| format!("SUDARE_ADMIN_PASSWORD: {e}"))?;
                    db.create_user("admin", &auth::hash_password(pw), "admin", auth::now())
                        .map_err(|e| e.to_string())?;
                }
                (None, None)
            }
        };
        let inner = Inner {
            cfg,
            db,
            engines,
            http,
            previews: Mutex::new(HashMap::new()),
            token_hash,
            local_user,
        };
        Ok((Self(Arc::new(inner)), printed))
    }

    pub fn engine(&self, strict: bool) -> &Engine {
        &self.engines[usize::from(strict)]
    }

    pub fn retention_days(&self) -> u32 {
        self.db
            .setting("retention_days")
            .ok()
            .flatten()
            .and_then(|v| v.parse().ok())
            .unwrap_or(self.cfg.retention_days)
    }

    /// Retention purge plus expired sessions and previews. Returns analyses removed.
    pub fn purge(&self) -> usize {
        let now = auth::now();
        let cutoff = now - i64::from(self.retention_days()) * 86_400;
        self.previews
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, p| p.created.elapsed() < PREVIEW_TTL);
        self.db.purge(cutoff, now).unwrap_or(0)
    }
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    extra: Option<Value>,
}

impl ApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            code,
            message: message.into(),
            extra: None,
        }
    }

    pub fn with(mut self, extra: Value) -> Self {
        self.extra = Some(extra);
        self
    }
}

impl From<db::DbError> for ApiError {
    fn from(e: db::DbError) -> Self {
        eprintln!("sudare: {e}");
        Self::new(500, "internal", "storage error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.code, "message": self.message });
        if let (Some(Value::Object(extra)), Value::Object(b)) = (self.extra, &mut body) {
            b.extend(extra);
        }
        (self.status, axum::Json(body)).into_response()
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(api::index))
        .route("/api/health", get(api::health))
        .route("/api/login", post(api::login))
        .route("/api/logout", post(api::logout))
        .route("/api/me", get(api::me))
        .route("/api/parsers", get(api::parsers))
        .route("/api/providers", get(api::providers))
        .route("/api/preview", post(api::preview))
        .route("/api/analyses", get(api::list).post(api::analyze))
        .route(
            "/api/analyses/{id}",
            get(api::get_analysis).delete(api::delete_analysis),
        )
        .route("/api/analyses/{id}/chat/preview", post(api::chat_preview))
        .route("/api/analyses/{id}/chat", post(api::chat))
        .route("/api/keys", get(api::list_keys))
        .route(
            "/api/keys/{name}",
            put(api::put_key).delete(api::delete_key),
        )
        .route("/api/users", get(api::list_users).post(api::create_user))
        .route("/api/users/{id}", delete(api::delete_user))
        .route(
            "/api/settings",
            get(api::get_settings).put(api::put_settings),
        )
        .fallback(api::not_found)
        .layer(DefaultBodyLimit::max(MAX_INPUT_BYTES + 64 * 1024))
        .layer(from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

const API_CSP: &str = "default-src 'none'; frame-ancestors 'none'";
const PAGE_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// Host allowlist (DNS rebinding), Origin check on state-changing requests, client
/// IP for throttling, and security headers on every response.
async fn guard(State(s): State<AppState>, mut req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut resp = if !s.cfg.allowed_hosts.contains(&host) {
        ApiError::new(421, "host_not_allowed", "this Host is not served here").into_response()
    } else if !auth::is_safe_method(req.method())
        && req.headers().get(header::ORIGIN).is_some_and(|o| {
            let o = o.to_str().unwrap_or("").to_ascii_lowercase();
            let o = o
                .strip_prefix("https://")
                .or_else(|| o.strip_prefix("http://"))
                .unwrap_or("");
            !s.cfg.allowed_hosts.iter().any(|h| h == o)
        })
    {
        ApiError::new(403, "origin", "cross-origin request refused").into_response()
    } else {
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| "unknown".to_string(), |c| c.0.ip().to_string());
        req.extensions_mut().insert(ClientIp(ip));
        let api = req.uri().path().starts_with("/api/");
        let mut r = next.run(req).await;
        if api {
            r.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        let csp = if api { API_CSP } else { PAGE_CSP };
        r.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(csp),
        );
        r
    };
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(API_CSP));
    resp
}

pub async fn serve(cfg: Config) -> Result<(), String> {
    let http = Arc::new(sudare_egress::http::ReqwestHttp::new().map_err(|e| e.to_string())?);
    let bind = cfg.bind;
    let first_host = cfg
        .allowed_hosts
        .first()
        .cloned()
        .unwrap_or_else(|| bind.to_string());
    let mode = cfg.mode;
    let (state, token) = AppState::new(cfg, http)?;
    let purger = state.clone();
    tokio::spawn(async move {
        loop {
            let n = purger.purge();
            if n > 0 {
                eprintln!("sudare: retention removed {n} analyses");
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    eprintln!("sudare: listening on http://{bind} ({mode:?} user mode)");
    match (mode, token) {
        // The fragment never reaches server logs or proxies.
        (UserMode::Single, Some(t)) => {
            eprintln!("sudare: open http://{first_host}/#token={}", t.as_str())
        }
        (UserMode::Single, None) => eprintln!("sudare: log in with SUDARE_TOKEN"),
        (UserMode::Multi, _) => eprintln!("sudare: log in with your account"),
    }
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
    .map_err(|e| e.to_string())
}
