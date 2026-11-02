//! LLM providers: Ollama (default, local), OpenAI, Anthropic, Gemini and any
//! OpenAI-compatible server. One struct, five request shapes.

use crate::http::{EgressRequest, Http, HttpError, send_with_retry};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::net::IpAddr;
use std::time::Duration;
use sudare_core::{MaskedPrompt, Role};
use url::Url;
use zeroize::Zeroizing;

/// An API key. Zeroed on drop; Debug never prints it.
pub struct ApiKey(Zeroizing<String>);

impl ApiKey {
    pub fn new(key: String) -> Option<Self> {
        let key = key.trim().to_string();
        (!key.is_empty()).then(|| Self(Zeroizing::new(key)))
    }
    pub fn from_env(var: &str) -> Option<Self> {
        std::env::var(var).ok().and_then(Self::new)
    }
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApiKey(***)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("{provider}: {source}")]
    Http {
        provider: String,
        #[source]
        source: HttpError,
    },
    #[error("{provider} returned HTTP {status}: {excerpt}")]
    Status {
        provider: String,
        status: u16,
        excerpt: String,
    },
    #[error("{0}: unexpected response shape")]
    Shape(String),
    #[error("{0} needs an API key: set {1}")]
    MissingKey(&'static str, &'static str),
    #[error("{0}")]
    Config(String),
}

pub struct LlmResponse {
    pub text: String,
    pub model: String,
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn name(&self) -> &str;
    fn model(&self) -> &str;
    fn base_url(&self) -> &Url;
    /// Character budget for log lines in the prompt.
    fn context_chars(&self) -> usize;
    /// True for loopback or a host listed in `local_hosts`. Anything else needs the
    /// mask preview confirmed before the first call.
    fn is_local(&self) -> bool;
    async fn complete(
        &self,
        prompt: &MaskedPrompt,
        schema: Option<&Value>,
        http: &dyn Http,
    ) -> Result<LlmResponse, LlmError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Ollama,
    OpenAi,
    Anthropic,
    Gemini,
    OpenAiCompatible,
}

impl ProviderKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Gemini => "gemini",
            Self::OpenAiCompatible => "openai-compatible",
        }
    }
    fn default_base(self) -> Option<&'static str> {
        match self {
            Self::Ollama => Some("http://127.0.0.1:11434"),
            Self::OpenAi => Some("https://api.openai.com/v1"),
            Self::Anthropic => Some("https://api.anthropic.com"),
            Self::Gemini => Some("https://generativelanguage.googleapis.com"),
            Self::OpenAiCompatible => None,
        }
    }
    fn default_model(self) -> Option<&'static str> {
        match self {
            // Apache-2.0 weights, ~5 GB, follows JSON schemas well.
            Self::Ollama => Some("qwen3:8b"),
            Self::OpenAi => Some("gpt-5-mini"),
            Self::Anthropic => Some("claude-sonnet-5-5"),
            Self::Gemini => Some("gemini-2.5-flash"),
            Self::OpenAiCompatible => None,
        }
    }
    /// Environment variable holding the key, if this provider needs one.
    pub fn key_env(self) -> Option<&'static str> {
        match self {
            Self::Ollama => None,
            Self::OpenAi => Some("OPENAI_API_KEY"),
            Self::Anthropic => Some("ANTHROPIC_API_KEY"),
            Self::Gemini => Some("GEMINI_API_KEY"),
            Self::OpenAiCompatible => Some("SUDARE_OPENAI_COMPAT_KEY"),
        }
    }
}

pub struct ProviderConfig {
    pub kind: ProviderKind,
    pub model: Option<String>,
    pub base_url: Option<String>,
    pub api_key: Option<ApiKey>,
    /// Ollama context window in tokens; set explicitly because Ollama truncates silently.
    pub num_ctx: u32,
    pub local_hosts: Vec<String>,
    pub max_input_chars: Option<usize>,
}

impl ProviderConfig {
    pub fn new(kind: ProviderKind) -> Self {
        Self {
            kind,
            model: None,
            base_url: None,
            api_key: kind.key_env().and_then(ApiKey::from_env).or_else(|| {
                (kind == ProviderKind::Gemini)
                    .then(|| ApiKey::from_env("GOOGLE_API_KEY"))
                    .flatten()
            }),
            num_ctx: 16_384,
            local_hosts: Vec::new(),
            max_input_chars: None,
        }
    }
}

struct Provider {
    kind: ProviderKind,
    model: String,
    base: Url,
    key: Option<ApiKey>,
    num_ctx: u32,
    local: bool,
    context_chars: usize,
}

pub fn build(cfg: ProviderConfig) -> Result<Box<dyn LlmProvider>, LlmError> {
    let kind = cfg.kind;
    let base = cfg
        .base_url
        .as_deref()
        .or(kind.default_base())
        .ok_or_else(|| LlmError::Config(format!("{} needs --base-url", kind.name())))?;
    let mut base = Url::parse(base)
        .map_err(|e| LlmError::Config(format!("invalid base URL {base:?}: {e}")))?;
    if !matches!(base.scheme(), "http" | "https")
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err(LlmError::Config(
            "base URL must be http(s) without credentials".into(),
        ));
    }
    if !base.path().ends_with('/') {
        let p = format!("{}/", base.path());
        base.set_path(&p);
    }
    let model = cfg
        .model
        .or(kind.default_model().map(str::to_string))
        .ok_or_else(|| LlmError::Config(format!("{} needs --model", kind.name())))?;
    if model.is_empty()
        || !model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:/-".contains(c))
        || model.contains("..")
    {
        return Err(LlmError::Config(format!("invalid model name {model:?}")));
    }
    let needs_key = matches!(
        kind,
        ProviderKind::OpenAi | ProviderKind::Anthropic | ProviderKind::Gemini
    );
    if needs_key && cfg.api_key.is_none() {
        return Err(LlmError::MissingKey(
            kind.name(),
            kind.key_env().unwrap_or(""),
        ));
    }
    let local = match base.host() {
        Some(url::Host::Domain(d)) => {
            d.eq_ignore_ascii_case("localhost")
                || cfg.local_hosts.iter().any(|h| h.eq_ignore_ascii_case(d))
        }
        Some(url::Host::Ipv4(ip)) => {
            ip.is_loopback()
                || cfg
                    .local_hosts
                    .iter()
                    .any(|h| h.parse::<IpAddr>() == Ok(IpAddr::V4(ip)))
        }
        Some(url::Host::Ipv6(ip)) => {
            ip.is_loopback()
                || cfg
                    .local_hosts
                    .iter()
                    .any(|h| h.parse::<IpAddr>() == Ok(IpAddr::V6(ip)))
        }
        None => false,
    };
    let context_chars = cfg.max_input_chars.unwrap_or(match kind {
        // Leave room for the system prompt, schema and the answer; ~3 chars per token.
        ProviderKind::Ollama => (cfg.num_ctx.saturating_sub(6_000) as usize * 3).max(8_000),
        _ => 100_000,
    });
    Ok(Box::new(Provider {
        kind,
        model,
        base,
        key: cfg.api_key,
        num_ctx: cfg.num_ctx,
        local,
        context_chars,
    }))
}

fn role(r: Role) -> &'static str {
    match r {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}

impl Provider {
    fn url(&self, path: &str) -> String {
        self.base
            .join(path)
            .map(String::from)
            .unwrap_or_else(|_| self.base.to_string())
    }

    fn openai_messages(prompt: &MaskedPrompt) -> Vec<Value> {
        prompt
            .messages()
            .iter()
            .map(|m| json!({ "role": role(m.role()), "content": m.content() }))
            .collect()
    }

    fn request(&self, prompt: &MaskedPrompt, schema: Option<&Value>) -> EgressRequest {
        let key = self.key.as_ref().map(ApiKey::expose).unwrap_or("");
        match self.kind {
            ProviderKind::Ollama => {
                let mut body = json!({
                    "model": self.model,
                    "stream": false,
                    "messages": Self::openai_messages(prompt),
                    "options": { "num_ctx": self.num_ctx, "temperature": 0 },
                });
                if let Some(s) = schema {
                    body["format"] = s.clone();
                }
                EgressRequest::post_json(self.url("api/chat"), &body)
                    .timeout(Duration::from_secs(900))
            }
            ProviderKind::OpenAi | ProviderKind::OpenAiCompatible => {
                let mut body =
                    json!({ "model": self.model, "messages": Self::openai_messages(prompt) });
                match (self.kind, schema) {
                    (ProviderKind::OpenAi, Some(s)) => {
                        body["response_format"] = json!({
                            "type": "json_schema",
                            "json_schema": { "name": "incident_analysis", "schema": s, "strict": false },
                        });
                    }
                    (ProviderKind::OpenAiCompatible, _) => body["temperature"] = json!(0),
                    _ => {}
                }
                let mut r = EgressRequest::post_json(self.url("chat/completions"), &body)
                    .timeout(Duration::from_secs(300));
                if !key.is_empty() {
                    r = r.header("authorization", &format!("Bearer {key}"));
                }
                r
            }
            ProviderKind::Anthropic => {
                let messages: Vec<Value> = prompt
                    .turns()
                    .map(|m| json!({ "role": role(m.role()), "content": m.content() }))
                    .collect();
                let body = json!({
                    "model": self.model,
                    "max_tokens": 8192,
                    "system": prompt.system().unwrap_or(""),
                    "messages": messages,
                });
                EgressRequest::post_json(self.url("v1/messages"), &body)
                    .timeout(Duration::from_secs(300))
                    .header("x-api-key", key)
                    .header("anthropic-version", "2023-06-01")
            }
            ProviderKind::Gemini => {
                let contents: Vec<Value> = prompt
                    .turns()
                    .map(|m| {
                        let r = if m.role() == Role::Assistant {
                            "model"
                        } else {
                            "user"
                        };
                        json!({ "role": r, "parts": [{ "text": m.content() }] })
                    })
                    .collect();
                let mut config = json!({ "temperature": 0 });
                if schema.is_some() {
                    config["responseMimeType"] = json!("application/json");
                }
                let body = json!({
                    "systemInstruction": { "parts": [{ "text": prompt.system().unwrap_or("") }] },
                    "contents": contents,
                    "generationConfig": config,
                });
                // Key in a header, never in the URL.
                EgressRequest::post_json(
                    self.url(&format!("v1beta/models/{}:generateContent", self.model)),
                    &body,
                )
                .timeout(Duration::from_secs(300))
                .header("x-goog-api-key", key)
            }
        }
    }

    fn text(&self, v: &Value) -> Option<String> {
        let join = |parts: &Vec<Value>, key: &str| -> String {
            parts
                .iter()
                .filter_map(|p| p.get(key).and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("")
        };
        match self.kind {
            ProviderKind::Ollama => v["message"]["content"].as_str().map(str::to_string),
            ProviderKind::OpenAi | ProviderKind::OpenAiCompatible => {
                v["choices"][0]["message"]["content"]
                    .as_str()
                    .map(str::to_string)
            }
            ProviderKind::Anthropic => v["content"].as_array().map(|parts| {
                let texts: Vec<Value> = parts
                    .iter()
                    .filter(|p| p["type"] == "text")
                    .cloned()
                    .collect();
                join(&texts, "text")
            }),
            ProviderKind::Gemini => v["candidates"][0]["content"]["parts"]
                .as_array()
                .map(|p| join(p, "text")),
        }
    }
}

#[async_trait]
impl LlmProvider for Provider {
    fn name(&self) -> &str {
        self.kind.name()
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn base_url(&self) -> &Url {
        &self.base
    }
    fn context_chars(&self) -> usize {
        self.context_chars
    }
    fn is_local(&self) -> bool {
        self.local
    }

    async fn complete(
        &self,
        prompt: &MaskedPrompt,
        schema: Option<&Value>,
        http: &dyn Http,
    ) -> Result<LlmResponse, LlmError> {
        let name = self.name().to_string();
        let resp = send_with_retry(http, self.request(prompt, schema), 4)
            .await
            .map_err(|source| LlmError::Http {
                provider: name.clone(),
                source,
            })?;
        if !(200..300).contains(&resp.status) {
            return Err(LlmError::Status {
                provider: name,
                status: resp.status,
                excerpt: resp.excerpt(),
            });
        }
        let v = resp.json().ok_or_else(|| LlmError::Shape(name.clone()))?;
        let text = self.text(&v).ok_or(LlmError::Shape(name))?;
        let model = v["model"].as_str().unwrap_or(&self.model).to_string();
        Ok(LlmResponse { text, model })
    }
}
