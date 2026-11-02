use async_trait::async_trait;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

#[derive(Clone)]
pub struct EgressRequest {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout: Duration,
}

/// Header values may be API keys: Debug shows only their names.
impl std::fmt::Debug for EgressRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("EgressRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &names)
            .field("body_bytes", &self.body.as_ref().map_or(0, Vec::len))
            .finish()
    }
}

impl EgressRequest {
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: Method::Get,
            url: url.into(),
            headers: vec![("accept".into(), "application/json".into())],
            body: None,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn post_json(url: impl Into<String>, body: &serde_json::Value) -> Self {
        let mut r = Self::get(url);
        r.method = Method::Post;
        r.headers
            .push(("content-type".into(), "application/json".into()));
        r.body = Some(serde_json::to_vec(body).expect("JSON value serializes"));
        r
    }

    pub fn post_form(url: impl Into<String>, pairs: &[(&str, &str)]) -> Self {
        let mut r = Self::get(url);
        r.method = Method::Post;
        r.headers.push((
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        r.body = Some(body.into_bytes());
        r
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }
}

#[derive(Debug, Clone)]
pub struct EgressResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl EgressResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }

    /// First 300 characters of the body on one line, for error messages.
    pub fn excerpt(&self) -> String {
        let s = String::from_utf8_lossy(&self.body);
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(300)
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("network error: {0}")]
    Transport(String),
    #[error("request timed out")]
    Timeout,
}

#[async_trait]
pub trait Http: Send + Sync {
    async fn send(&self, req: EgressRequest) -> Result<EgressResponse, HttpError>;
}

/// Production client: rustls with the OS trust store, HTTPS_PROXY honoured.
pub struct ReqwestHttp {
    client: reqwest::Client,
}

impl ReqwestHttp {
    pub fn new() -> Result<Self, HttpError> {
        let client = reqwest::Client::builder()
            .user_agent(concat!("sudare/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(map_err)?;
        Ok(Self { client })
    }
}

fn map_err(e: reqwest::Error) -> HttpError {
    if e.is_timeout() {
        HttpError::Timeout
    } else {
        // Without the URL: some providers put keys in query strings.
        HttpError::Transport(e.without_url().to_string())
    }
}

#[async_trait]
impl Http for ReqwestHttp {
    async fn send(&self, req: EgressRequest) -> Result<EgressResponse, HttpError> {
        let mut b = match req.method {
            Method::Get => self.client.get(&req.url),
            Method::Post => self.client.post(&req.url),
        }
        .timeout(req.timeout);
        for (k, v) in &req.headers {
            b = b.header(k.as_str(), v.as_str());
        }
        if let Some(body) = req.body {
            b = b.body(body);
        }
        let resp = b.send().await.map_err(map_err)?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = resp.bytes().await.map_err(map_err)?.to_vec();
        Ok(EgressResponse {
            status,
            headers,
            body,
        })
    }
}

/// Retry 429 / 503 and network errors, honouring Retry-After (capped at 60 s).
pub async fn send_with_retry(
    http: &dyn Http,
    req: EgressRequest,
    attempts: u32,
) -> Result<EgressResponse, HttpError> {
    let attempts = attempts.max(1);
    for attempt in 1..=attempts {
        let backoff = Duration::from_secs(2u64.pow(attempt).min(60));
        match http.send(req.clone()).await {
            Ok(r) if (r.status == 429 || r.status == 503) && attempt < attempts => {
                let wait = r
                    .header("retry-after")
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map_or(backoff, |s| Duration::from_secs(s.min(60)));
                tokio::time::sleep(wait).await;
            }
            Err(_) if attempt < attempts => tokio::time::sleep(backoff).await,
            other => return other,
        }
    }
    unreachable!("the last attempt always returns")
}
