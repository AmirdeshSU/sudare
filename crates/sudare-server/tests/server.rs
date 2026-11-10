//! End-to-end API tests through the real router and middleware. Providers are faked
//! by a recording `Http`; nothing touches the network.

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sudare_egress::http::{EgressRequest, EgressResponse, Http, HttpError};
use sudare_server::{AppState, Config, router};
use tower::ServiceExt;

const HOST: &str = "127.0.0.1:8080";
const TOKEN: &str = "test-login-token-0123456789abcdef0123";
const LOG: &str = "<34>Oct 29 14:11:40 fw01 sshd[22]: Failed password for jdoe from 198.51.100.23 user=jdoe host=ws-17.corp.local src=10.20.30.40\n";
const SENSITIVE: &[&str] = &["fw01", "jdoe", "ws-17.corp.local", "10.20.30.40"];

#[derive(Default)]
struct Recorder {
    log: Mutex<Vec<EgressRequest>>,
}

impl Recorder {
    fn bodies(&self) -> String {
        self.log
            .lock()
            .unwrap()
            .iter()
            .map(|r| {
                format!(
                    "{} {:?} {}",
                    r.url,
                    r.headers,
                    String::from_utf8_lossy(r.body.as_deref().unwrap_or(&[]))
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase()
    }
}

fn first_token(body: &str) -> String {
    let logs = &body[body.find("<<<LOGS").unwrap_or(0)..];
    let start = logs
        .find("[[USER_")
        .or_else(|| logs.find("[["))
        .unwrap_or(0);
    let end = logs[start..].find("]]").map_or(start, |e| start + e + 2);
    logs[start..end].to_string()
}

#[async_trait]
impl Http for Recorder {
    async fn send(&self, req: EgressRequest) -> Result<EgressResponse, HttpError> {
        let body = String::from_utf8_lossy(req.body.as_deref().unwrap_or(&[])).into_owned();
        let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let structured = parsed.get("format").is_some() || parsed.get("response_format").is_some();
        let url = req.url.clone();
        self.log.lock().unwrap().push(req);
        let token = first_token(&body);
        let content = if structured {
            json!({
                "summary": format!("{token} brute-forced then logged in"),
                "verdict": "likely_true_positive",
                "severity": { "level": "high", "rationale": "r" },
                "confidence": { "score": 0.7, "would_change_it": "x" },
                "timeline": [], "entities": [], "attack_techniques": [{ "id": "T1110", "name": "x", "evidence": "e", "evidence_lines": [1] }],
                "recommended_actions": { "containment": [], "investigation": [], "eradication": [] },
                "open_questions": []
            })
            .to_string()
        } else {
            "The answer mentions [[USER_1]] which may not exist.".to_string()
        };
        let v = if url.contains("/api/chat") {
            json!({ "model": "m", "message": { "content": content } })
        } else if url.contains("chat/completions") {
            json!({ "model": "m", "choices": [{ "message": { "content": content } }] })
        } else if url.ends_with("triggeringEvents?incidentId=42") {
            json!({ "data": [{ "eventType": "Win-Security-4625", "receiveTime": 1793232000000u64,
                "rawMessage": "4625 failed logon user=hgupta src=198.51.100.33" }], "result": { "code": 0 } })
        } else {
            return Ok(EgressResponse {
                status: 404,
                headers: vec![],
                body: b"{}".to_vec(),
            });
        };
        Ok(EgressResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&v).unwrap(),
        })
    }
}

fn temp_dir() -> std::path::PathBuf {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    std::env::temp_dir().join(format!(
        "sudare-test-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    ))
}

const KEY: &str = "3f1a9c2e7b4d8e6f0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f50617";

fn config(extra: &[(&str, &str)]) -> Config {
    let dir = temp_dir();
    let mut env: HashMap<String, String> = HashMap::from([
        ("SUDARE_SECRET_KEY".into(), KEY.into()),
        ("SUDARE_DATA_DIR".into(), dir.to_string_lossy().into_owned()),
        ("SUDARE_TOKEN".into(), TOKEN.into()),
    ]);
    for (k, v) in extra {
        env.insert(k.to_string(), v.to_string());
    }
    Config::from_lookup(|k| env.get(k).cloned()).unwrap()
}

struct Client {
    app: Router,
    state: AppState,
    http: Arc<Recorder>,
    cookie: String,
    csrf: String,
}

impl Client {
    fn new(cfg: Config) -> Self {
        let http = Arc::new(Recorder::default());
        let (state, _) = AppState::new(cfg, http.clone()).unwrap();
        Self {
            app: router(state.clone()),
            state,
            http,
            cookie: String::new(),
            csrf: String::new(),
        }
    }

    async fn raw(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, Value) {
        let mut b = Request::builder()
            .method(method)
            .uri(path)
            .header("host", HOST);
        if !self.cookie.is_empty() {
            b = b.header("cookie", &self.cookie);
        }
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string())),
            None => b.body(Body::empty()),
        }
        .unwrap();
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (resp.status(), resp.headers().clone());
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        let csrf = self.csrf.clone();
        let (s, _, v) = self
            .raw(method, path, body, &[("x-csrf-token", &csrf)])
            .await;
        (s, v)
    }

    async fn login(&mut self, body: Value) -> StatusCode {
        let (status, headers, v) = self.raw("POST", "/api/login", Some(body), &[]).await;
        if status == StatusCode::OK {
            let cookies: Vec<String> = headers
                .get_all("set-cookie")
                .iter()
                .map(|v| v.to_str().unwrap().to_string())
                .collect();
            assert!(cookies.iter().any(|c| c.starts_with("sudare_session=")
                && c.contains("HttpOnly")
                && c.contains("SameSite=Strict")));
            self.cookie = cookies
                .iter()
                .map(|c| c.split(';').next().unwrap())
                .collect::<Vec<_>>()
                .join("; ");
            self.csrf = v["csrf"].as_str().unwrap().to_string();
        }
        status
    }
}

#[test]
fn refuses_to_start_with_weak_secrets() {
    let try_cfg = |pairs: &[(&str, &str)]| {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| env.get(k).cloned())
    };
    let dir = temp_dir();
    let d = dir.to_str().unwrap();
    assert!(try_cfg(&[("SUDARE_DATA_DIR", d)]).is_err(), "missing key");
    assert!(try_cfg(&[("SUDARE_SECRET_KEY", "changeme"), ("SUDARE_DATA_DIR", d)]).is_err());
    assert!(
        try_cfg(&[
            ("SUDARE_SECRET_KEY", &"00".repeat(32)),
            ("SUDARE_DATA_DIR", d)
        ])
        .is_err(),
        "zero key"
    );
    assert!(
        try_cfg(&[
            ("SUDARE_SECRET_KEY", KEY),
            ("SUDARE_DATA_DIR", d),
            ("SUDARE_TOKEN", "short")
        ])
        .is_err()
    );
    assert!(
        try_cfg(&[
            ("SUDARE_SECRET_KEY", KEY),
            ("SUDARE_DATA_DIR", d),
            ("SUDARE_BIND", "0.0.0.0:8080")
        ])
        .is_err(),
        "public bind needs allowed hosts"
    );
    let multi = config(&[
        ("SUDARE_MODE", "multi"),
        ("SUDARE_ADMIN_PASSWORD", "Admin@123"),
    ]);
    assert!(
        AppState::new(multi, Arc::new(Recorder::default())).is_err(),
        "placeholder admin password"
    );
    let multi = config(&[("SUDARE_MODE", "multi")]);
    assert!(
        AppState::new(multi, Arc::new(Recorder::default())).is_err(),
        "no admin password on first start"
    );
}

#[tokio::test]
async fn host_allowlist_origin_check_and_headers() {
    let c = Client::new(config(&[]));
    let req = Request::builder()
        .uri("/api/health")
        .header("host", "evil.example.com")
        .body(Body::empty())
        .unwrap();
    let resp = c.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::MISDIRECTED_REQUEST);

    let (status, headers, _) = c.raw("GET", "/api/health", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );

    // The UI page: strict CSP (WebAssembly allowed, no inline or eval script).
    let (status, headers, _) = c.raw("GET", "/", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("script-src 'self' 'wasm-unsafe-eval';"),
        "{csp}"
    );
    assert!(
        !csp.contains("unsafe-inline") && !csp.contains("'unsafe-eval'"),
        "{csp}"
    );
    for (method, path) in [
        ("GET", "/api/nope"),
        ("POST", "/"),
        ("GET", "/no-such-file.js"),
    ] {
        let (status, _, _) = c.raw(method, path, None, &[]).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
    }
    let (_, _, body) = c.raw("GET", "/api/health", None, &[]).await;
    assert_eq!(body["mode"], "single");

    let (status, _, _) = c
        .raw(
            "POST",
            "/api/login",
            Some(json!({ "token": TOKEN })),
            &[("origin", "https://evil.example.com")],
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = c.raw("GET", "/api/me", None, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn single_user_analysis_history_and_chat() {
    let mut c = Client::new(config(&[]));
    assert_eq!(
        c.login(json!({ "token": "wrong-token-wrong-token-wrong-token" }))
            .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(c.login(json!({ "token": TOKEN })).await, StatusCode::OK);

    // CSRF: a state-changing call without the header is refused.
    let (status, _, _) = c
        .raw("POST", "/api/preview", Some(json!({ "text": LOG })), &[])
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, preview) = c
        .call("POST", "/api/preview", Some(json!({ "text": LOG })))
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let masked = preview["masked"].as_str().unwrap();
    for v in SENSITIVE {
        assert!(!masked.contains(v), "{v} in preview");
    }

    // Ollama on loopback is local: no confirmation needed.
    let (status, done) = c
        .call(
            "POST",
            "/api/analyses",
            Some(json!({ "preview_id": preview["preview_id"], "provider": "ollama" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let id = done["id"].as_str().unwrap().to_string();
    let summary = done["report"]["analysis"]["summary"].as_str().unwrap();
    assert!(summary.contains("jdoe"), "summary not unmasked: {summary}");

    // The preview is single-use.
    let (status, _) = c
        .call(
            "POST",
            "/api/analyses",
            Some(json!({ "preview_id": preview["preview_id"], "provider": "ollama" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (_, list) = c.call("GET", "/api/analyses", None).await;
    assert_eq!(list.as_array().unwrap().len(), 1);

    let (status, chat) = c
        .call(
            "POST",
            &format!("/api/analyses/{id}/chat"),
            Some(json!({ "question": "did jdoe log in on fw01?", "provider": "ollama" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{chat}");
    let (_, full) = c.call("GET", &format!("/api/analyses/{id}"), None).await;
    assert_eq!(full["chat"][0]["question"], "did jdoe log in on fw01?");
    assert!(!full["masked_input"].as_str().unwrap().contains("jdoe"));

    let sent = c.http.bodies();
    for v in SENSITIVE {
        assert!(!sent.contains(v), "{v} reached a provider");
    }
    for blob in c.state.db.raw_sealed_sessions().unwrap() {
        let text = String::from_utf8_lossy(&blob).to_lowercase();
        assert!(
            SENSITIVE.iter().all(|v| !text.contains(v)),
            "sealed session has plaintext"
        );
    }

    let (status, _) = c.call("DELETE", &format!("/api/analyses/{id}"), None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = c.call("GET", &format!("/api/analyses/{id}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(c.state.db.raw_sealed_sessions().unwrap().is_empty());
}

#[tokio::test]
async fn cloud_provider_needs_the_preview_digest_and_keys_stay_secret() {
    let mut c = Client::new(config(&[]));
    assert_eq!(c.login(json!({ "token": TOKEN })).await, StatusCode::OK);
    let key = "sk-test-0123456789-SECRETVALUE";
    let (status, _) = c
        .call("PUT", "/api/keys/openai", Some(json!({ "key": key })))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, keys) = c.call("GET", "/api/keys", None).await;
    let listed = keys.to_string();
    assert!(
        !listed.contains("SECRETVALUE") && listed.contains("…ALUE"),
        "{listed}"
    );

    let (_, preview) = c
        .call("POST", "/api/preview", Some(json!({ "text": LOG })))
        .await;
    let pid = preview["preview_id"].clone();
    let (status, err) = c
        .call(
            "POST",
            "/api/analyses",
            Some(json!({ "preview_id": pid, "provider": "openai" })),
        )
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(err["digest"], preview["digest"]);
    let (status, _) = c
        .call("POST", "/api/analyses", Some(json!({ "preview_id": pid, "provider": "openai", "confirm_digest": "0".repeat(64) })))
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert!(
        c.http.log.lock().unwrap().is_empty(),
        "nothing may be sent before confirmation"
    );

    let (status, done) = c
        .call("POST", "/api/analyses", Some(json!({ "preview_id": pid, "provider": "openai", "confirm_digest": preview["digest"] })))
        .await;
    assert_eq!(status, StatusCode::OK, "{done}");
    let bearer = c.http.log.lock().unwrap()[0]
        .headers
        .iter()
        .any(|(k, v)| k == "authorization" && v == &format!("Bearer {key}"));
    assert!(bearer);

    // Chat to a cloud provider also needs the masked question's digest.
    let id = done["id"].as_str().unwrap();
    let q = json!({ "question": "is jdoe an admin?", "provider": "openai" });
    let (status, _) = c
        .call("POST", &format!("/api/analyses/{id}/chat"), Some(q.clone()))
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    let (_, p) = c
        .call(
            "POST",
            &format!("/api/analyses/{id}/chat/preview"),
            Some(json!({ "question": "is jdoe an admin?" })),
        )
        .await;
    assert!(!p["masked_question"].as_str().unwrap().contains("jdoe"));
    let mut q = q;
    q["confirm_digest"] = p["digest"].clone();
    let (status, _) = c
        .call("POST", &format!("/api/analyses/{id}/chat"), Some(q))
        .await;
    assert_eq!(status, StatusCode::OK);

    let db_bytes = std::fs::read(c.state.cfg.data_dir.join("sudare.sqlite")).unwrap();
    let wal = std::fs::read(c.state.cfg.data_dir.join("sudare.sqlite-wal")).unwrap_or_default();
    for bytes in [db_bytes, wal] {
        assert!(
            !String::from_utf8_lossy(&bytes).contains("SECRETVALUE"),
            "API key stored in clear"
        );
    }
}

#[tokio::test]
async fn multi_user_isolation_roles_and_lockout() {
    let cfg = config(&[
        ("SUDARE_MODE", "multi"),
        ("SUDARE_ADMIN_PASSWORD", "correct-horse-battery"),
    ]);
    let mut admin = Client::new(cfg);
    for _ in 0..5 {
        assert_eq!(
            admin
                .login(json!({ "username": "admin", "password": "wrong-password!" }))
                .await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        admin
            .login(json!({ "username": "admin", "password": "correct-horse-battery" }))
            .await,
        StatusCode::TOO_MANY_REQUESTS,
        "locked out after 5 failures"
    );
    admin.state.db.clear_failures("unknown|admin").unwrap();
    assert_eq!(
        admin
            .login(json!({ "username": "ADMIN", "password": "correct-horse-battery" }))
            .await,
        StatusCode::OK
    );

    let (status, _) = admin
        .call(
            "POST",
            "/api/users",
            Some(json!({ "username": "analyst", "password": "another-long-password" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, preview) = admin
        .call("POST", "/api/preview", Some(json!({ "text": LOG })))
        .await;
    let (_, done) = admin
        .call(
            "POST",
            "/api/analyses",
            Some(json!({ "preview_id": preview["preview_id"], "provider": "ollama" })),
        )
        .await;
    let id = done["id"].as_str().unwrap().to_string();

    let mut analyst = Client {
        cookie: String::new(),
        csrf: String::new(),
        app: admin.app.clone(),
        state: admin.state.clone(),
        http: admin.http.clone(),
    };
    assert_eq!(
        analyst
            .login(json!({ "username": "analyst", "password": "another-long-password" }))
            .await,
        StatusCode::OK
    );
    let (status, _) = analyst
        .call("GET", &format!("/api/analyses/{id}"), None)
        .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "analyses are private to their owner"
    );
    let (status, _) = analyst.call("GET", "/api/users", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // The analyst can't use the admin's preview either.
    let (_, p2) = admin
        .call("POST", "/api/preview", Some(json!({ "text": LOG })))
        .await;
    let (status, _) = analyst
        .call(
            "POST",
            "/api/analyses",
            Some(json!({ "preview_id": p2["preview_id"], "provider": "ollama" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn retention_purges_old_analyses() {
    let mut c = Client::new(config(&[]));
    c.login(json!({ "token": TOKEN })).await;
    let (_, preview) = c
        .call("POST", "/api/preview", Some(json!({ "text": LOG })))
        .await;
    c.call(
        "POST",
        "/api/analyses",
        Some(json!({ "preview_id": preview["preview_id"], "provider": "ollama", "enrich": false })),
    )
    .await;
    assert_eq!(c.state.purge(), 0);
    c.state.db.backdate_analyses(1).unwrap();
    assert_eq!(c.state.purge(), 1);
    let (_, list) = c.call("GET", "/api/analyses", None).await;
    assert!(list.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn fortisiem_pull_feeds_the_preview() {
    let mut off = Client::new(config(&[]));
    off.login(json!({ "token": TOKEN })).await;
    let (_, me) = off.call("GET", "/api/me", None).await;
    assert_eq!(me["connectors"], json!([]));
    let (status, _) = off
        .call(
            "POST",
            "/api/pull/fortisiem",
            Some(json!({ "incident_id": "42" })),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let mut c = Client::new(config(&[
        ("SUDARE_FORTISIEM_URL", "https://siem.example.com"),
        ("SUDARE_FORTISIEM_TOKEN", "siem-token-1"),
    ]));
    let (status, _) = c
        .call(
            "POST",
            "/api/pull/fortisiem",
            Some(json!({ "incident_id": "42" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "needs a session");
    c.login(json!({ "token": TOKEN })).await;
    let (_, me) = c.call("GET", "/api/me", None).await;
    assert_eq!(me["connectors"], json!(["fortisiem"]));

    let (status, v) = c
        .call(
            "POST",
            "/api/pull/fortisiem",
            Some(json!({ "incident_id": "4&x=1" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    let (status, v) = c
        .call(
            "POST",
            "/api/pull/fortisiem",
            Some(json!({ "incident_id": "7" })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{v}");

    let (status, pulled) = c
        .call(
            "POST",
            "/api/pull/fortisiem",
            Some(json!({ "incident_id": "42" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{pulled}");
    assert_eq!(pulled["parser"], "fortisiem");
    let (status, preview) = c
        .call(
            "POST",
            "/api/preview",
            Some(json!({ "text": pulled["text"] })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    let masked = preview["masked"].as_str().unwrap();
    assert!(masked.contains("2026-10-29T00:00:00Z") && !masked.contains("hgupta"));
    let sent = c.http.bodies();
    assert!(sent.contains("bearer siem-token-1") && sent.contains("incidentid=42"));
    assert!(!sent.contains("incidentid=7&") && !sent.contains("x=1"));
}
