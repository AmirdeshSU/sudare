use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Byte offsets into the normalized input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
    pub fn overlaps(&self, o: &Span) -> bool {
        self.start < o.end && o.start < self.end
    }
    pub fn contains(&self, o: &Span) -> bool {
        self.start <= o.start && o.end <= self.end
    }
}

/// One log record. Parsers never panic: a record they cannot read comes back with
/// `error` set and no fields, and its text is still extracted and masked.
#[derive(Debug, Clone, Serialize)]
pub struct Event {
    pub index: usize,
    pub span: Span,
    /// First and last line, 1-based.
    pub lines: (u32, u32),
    pub timestamp: Option<String>,
    /// Flattened native field names, e.g. `winlog.event_data.TargetUserName`.
    pub fields: IndexMap<String, String>,
    pub format: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Ip,
    Hostname,
    Fqdn,
    Url,
    Email,
    Username,
    Md5,
    Sha1,
    Sha256,
    FilePath,
    Mac,
    Process,
    Cve,
    Secret,
    /// Token-shaped text already present in the input, masked so it can't pose as a token.
    Literal,
    /// A custom rule, a denylist term or a built-in extra such as `SID`.
    Custom(String),
}

impl EntityType {
    /// Names used in mapping files and policies.
    pub fn from_name(s: &str) -> Option<Self> {
        Some(match s {
            "ip" => Self::Ip,
            "hostname" => Self::Hostname,
            "fqdn" => Self::Fqdn,
            "url" => Self::Url,
            "email" => Self::Email,
            "username" => Self::Username,
            // Refined to md5/sha1/sha256 by length at extraction time.
            "hash" | "sha256" => Self::Sha256,
            "md5" => Self::Md5,
            "sha1" => Self::Sha1,
            "file_path" => Self::FilePath,
            "mac" => Self::Mac,
            "process" => Self::Process,
            "cve" => Self::Cve,
            "secret" => Self::Secret,
            _ => return None,
        })
    }

    pub fn label(&self) -> String {
        match self {
            Self::Custom(n) => n.to_ascii_lowercase(),
            other => serde_json::to_value(other)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Internal,
    Public,
    Reserved,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Regex,
    Field(String),
    KeyValue(String),
    Rule(String),
    Denylist,
    /// Another occurrence of a value already chosen for masking.
    Propagated,
}

#[derive(Debug, Clone, Serialize)]
pub struct Entity {
    pub kind: EntityType,
    /// Text exactly as it appears at `span`.
    pub value: String,
    /// Canonical form; one token per (prefix, normalized) pair.
    pub normalized: String,
    pub span: Span,
    pub scope: Scope,
    pub source: Source,
}

impl Entity {
    pub fn new(kind: EntityType, text: &str, span: Span, source: Source) -> Self {
        let value = text[span.start..span.end].to_string();
        let normalized = normalize_value(&kind, &value);
        Self {
            kind,
            value,
            normalized,
            span,
            scope: Scope::None,
            source,
        }
    }
}

pub fn normalize_value(kind: &EntityType, v: &str) -> String {
    use EntityType::*;
    match kind {
        Ip => v
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.to_canonical().to_string())
            .unwrap_or_else(|_| v.to_ascii_lowercase()),
        Mac => {
            let hex: String = v.chars().filter(|c| c.is_ascii_hexdigit()).collect();
            let hex = hex.to_ascii_lowercase();
            hex.as_bytes()
                .chunks(2)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect::<Vec<_>>()
                .join(":")
        }
        Url => url::Url::parse(v)
            .map(|u| u.to_string())
            .unwrap_or_else(|_| v.to_ascii_lowercase()),
        // JSON and CEF exports double the backslash in DOMAIN\user and Windows paths.
        Username | FilePath => v.replace("\\\\", "\\").to_ascii_lowercase(),
        Hostname | Fqdn | Email | Md5 | Sha1 | Sha256 | Process | Cve => {
            v.trim_end_matches('.').to_ascii_lowercase()
        }
        Secret | Literal | Custom(_) => v.to_string(),
    }
}
