//! SIEM connectors. Pull only: they read alerts from your SIEM and never write back.
//! What they return is real log data, so it goes through masking like any other input.

use crate::http::{EgressRequest, Http, HttpError, send_with_retry};
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    /// Bad configuration or input; nothing was sent.
    #[error("{0}")]
    Config(String),
    #[error("FortiSIEM: {0}")]
    Remote(String),
    #[error(transparent)]
    Http(#[from] HttpError),
}

fn remote(m: impl Into<String>) -> SiemError {
    SiemError::Remote(m.into())
}

#[derive(Clone)]
enum Auth {
    Token(Zeroizing<String>),
    Client {
        id: String,
        secret: Zeroizing<String>,
    },
}

/// FortiSIEM public REST API (`/phoenix/rest/pub`).
#[derive(Clone)]
pub struct FortiSiem {
    base: String,
    auth: Auth,
}

/// Credentials stay out of Debug output.
impl std::fmt::Debug for FortiSiem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FortiSiem")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl FortiSiem {
    /// Reads `SUDARE_FORTISIEM_URL` plus `SUDARE_FORTISIEM_TOKEN`, or
    /// `SUDARE_FORTISIEM_CLIENT_ID` and `SUDARE_FORTISIEM_CLIENT_SECRET`.
    /// `None` when the URL is unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, SiemError> {
        let Some(base) = get("SUDARE_FORTISIEM_URL") else {
            return Ok(None);
        };
        let base = base.trim().trim_end_matches('/').to_string();
        let u = url::Url::parse(&base)
            .map_err(|e| SiemError::Config(format!("SUDARE_FORTISIEM_URL: {e}")))?;
        let loopback = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if u.scheme() != "https" && !(u.scheme() == "http" && loopback) {
            return Err(SiemError::Config(
                "SUDARE_FORTISIEM_URL must be https:// (credentials are sent to it)".into(),
            ));
        }
        let auth = match (
            get("SUDARE_FORTISIEM_TOKEN"),
            get("SUDARE_FORTISIEM_CLIENT_ID"),
            get("SUDARE_FORTISIEM_CLIENT_SECRET"),
        ) {
            (Some(t), _, _) => Auth::Token(Zeroizing::new(t)),
            (None, Some(id), Some(secret)) => Auth::Client {
                id,
                secret: Zeroizing::new(secret),
            },
            _ => {
                return Err(SiemError::Config(
                    "set SUDARE_FORTISIEM_TOKEN, or SUDARE_FORTISIEM_CLIENT_ID and SUDARE_FORTISIEM_CLIENT_SECRET".into(),
                ));
            }
        };
        Ok(Some(Self { base, auth }))
    }

    pub fn base_url(&self) -> &str {
        &self.base
    }

    // ponytail: new OAuth token per pull; cache it (expires_in) if pulls get frequent.
    async fn token(&self, http: &dyn Http) -> Result<Zeroizing<String>, SiemError> {
        let (id, secret) = match &self.auth {
            Auth::Token(t) => return Ok(t.clone()),
            Auth::Client { id, secret } => (id, secret),
        };
        let req = EgressRequest::post_form(
            format!("{}/phoenix/rest/pub/security/oauth/token", self.base),
            &[
                ("grant_type", "client_credentials"),
                ("client_id", id),
                ("client_secret", secret),
            ],
        );
        let r = send_with_retry(http, req, 3).await?;
        if r.status != 200 {
            return Err(remote(format!(
                "token request failed (HTTP {}); check the client id and secret",
                r.status
            )));
        }
        r.json()
            .and_then(|v| v["access_token"].as_str().map(|s| Zeroizing::new(s.into())))
            .ok_or_else(|| remote("token response has no access_token"))
    }

    /// The events that triggered `incident_id`, as the API's own JSON
    /// (`{"data": [...]}`), which the `fortisiem` parser reads. A numeric
    /// `receiveTime` (epoch milliseconds) is rewritten as RFC 3339.
    pub async fn triggering_events(
        &self,
        http: &dyn Http,
        incident_id: &str,
    ) -> Result<String, SiemError> {
        let id = incident_id.trim();
        if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(SiemError::Config("incident id must be a number".into()));
        }
        let token = self.token(http).await?;
        let req = EgressRequest::get(format!(
            "{}/phoenix/rest/pub/incident/triggeringEvents?incidentId={id}",
            self.base
        ))
        .header("authorization", &format!("Bearer {}", token.as_str()))
        .timeout(Duration::from_secs(60));
        let r = send_with_retry(http, req, 3).await?;
        match r.status {
            200 => {}
            401 | 403 => {
                return Err(remote(
                    "authentication failed; check the token or client credentials",
                ));
            }
            400 | 404 => {
                return Err(remote(format!(
                    "incident {id} not found (wrong id, or past FortiSIEM retention)"
                )));
            }
            s => return Err(remote(format!("HTTP {s}: {}", r.excerpt()))),
        }
        let mut v = r.json().ok_or_else(|| remote("response is not JSON"))?;
        let events = v
            .get_mut("data")
            .and_then(|d| d.as_array_mut())
            .ok_or_else(|| remote("response has no data array"))?;
        if events.is_empty() {
            return Err(remote(format!(
                "incident {id} has no triggering events on record"
            )));
        }
        for e in events.iter_mut() {
            if let Some(ms) = e.get("receiveTime").and_then(|t| t.as_u64()) {
                e["receiveTime"] = sudare_core::report::rfc3339(ms / 1000).into();
            }
        }
        Ok(serde_json::to_string_pretty(&v).expect("JSON value serializes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::EgressResponse;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake(Mutex<Vec<EgressRequest>>);

    #[async_trait]
    impl Http for Fake {
        async fn send(&self, req: EgressRequest) -> Result<EgressResponse, HttpError> {
            let (status, body) = if req.url.ends_with("/oauth/token") {
                (200, r#"{"access_token":"tok-1","expires_in":7200}"#)
            } else if req.url.ends_with("incidentId=42") {
                (
                    200,
                    r#"{"data":[{"eventType":"Win-Security-4625","receiveTime":1793232000000,
                        "rawMessage":"4625 failed logon user=hgupta src=198.51.100.33"}],"result":{"code":0}}"#,
                )
            } else {
                (400, r#"{"result":{"code":1}}"#)
            };
            self.0.lock().unwrap().push(req);
            Ok(EgressResponse {
                status,
                headers: vec![],
                body: body.into(),
            })
        }
    }

    fn conf(pairs: &[(&str, &str)]) -> Result<Option<FortiSiem>, SiemError> {
        let env: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        FortiSiem::from_lookup(|k| env.get(k).cloned())
    }

    const CLIENT: &[(&str, &str)] = &[
        ("SUDARE_FORTISIEM_URL", "https://siem.example.com/"),
        ("SUDARE_FORTISIEM_CLIENT_ID", "cid"),
        ("SUDARE_FORTISIEM_CLIENT_SECRET", "csecret"),
    ];

    #[test]
    fn config_rules() {
        assert!(conf(&[]).unwrap().is_none());
        let plain = [
            ("SUDARE_FORTISIEM_URL", "http://siem.example.com"),
            ("SUDARE_FORTISIEM_TOKEN", "t"),
        ];
        assert!(conf(&plain).is_err(), "plain http to a remote host");
        let local = [
            ("SUDARE_FORTISIEM_URL", "http://127.0.0.1:9"),
            ("SUDARE_FORTISIEM_TOKEN", "t"),
        ];
        assert!(conf(&local).unwrap().is_some());
        assert!(conf(&CLIENT[..2]).is_err(), "client id without secret");
        let f = conf(CLIENT).unwrap().unwrap();
        assert!(!format!("{f:?}").contains("csecret"));
    }

    #[tokio::test]
    async fn pulls_triggering_events() {
        let f = conf(CLIENT).unwrap().unwrap();
        let http = Fake::default();
        let text = f.triggering_events(&http, " 42 ").await.unwrap();
        let log = http.0.lock().unwrap();
        assert_eq!(log.len(), 2);
        let form = String::from_utf8_lossy(log[0].body.as_deref().unwrap());
        assert!(form.contains("client_id=cid") && form.contains("client_secret=csecret"));
        assert!(
            log[1]
                .headers
                .iter()
                .any(|(k, v)| k == "authorization" && v == "Bearer tok-1")
        );
        drop(log);
        assert!(text.contains("\"2026-10-29T00:00:00Z\""), "{text}");

        let p = sudare_core::Engine::new(sudare_core::Policy::default())
            .unwrap()
            .prepare(&text, None, [1; 32])
            .unwrap();
        assert_eq!(p.parser, "fortisiem");
        assert!(!p.input.text().contains("hgupta"));
    }

    #[tokio::test]
    async fn errors() {
        let f = conf(CLIENT).unwrap().unwrap();
        let http = Fake::default();
        for bad in ["", "42; rm", "1&x=2", "../x"] {
            assert!(matches!(
                f.triggering_events(&http, bad).await,
                Err(SiemError::Config(_))
            ));
        }
        assert!(
            http.0.lock().unwrap().is_empty(),
            "nothing sent for bad ids"
        );
        let e = f.triggering_events(&http, "7").await.unwrap_err();
        assert!(e.to_string().contains("not found"), "{e}");
    }
}
