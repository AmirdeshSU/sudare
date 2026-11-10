//! Server configuration from the environment. Refuses to start on missing, short or
//! placeholder secrets.

use std::net::SocketAddr;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserMode {
    /// One local user; log in with the token printed at startup.
    Single,
    /// Accounts with passwords; an admin is bootstrapped from SUDARE_ADMIN_PASSWORD.
    Multi,
}

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub mode: UserMode,
    pub data_dir: PathBuf,
    pub secret_key: Zeroizing<[u8; 32]>,
    pub token: Option<Zeroizing<String>>,
    pub admin_password: Option<Zeroizing<String>>,
    /// Accepted `Host` header values (DNS-rebinding protection).
    pub allowed_hosts: Vec<String>,
    pub cookie_secure: bool,
    pub retention_days: u32,
    pub policy: Option<PathBuf>,
    pub ollama_url: Option<String>,
    pub compat_url: Option<String>,
    pub compat_model: Option<String>,
    pub local_hosts: Vec<String>,
    pub num_ctx: u32,
    /// Read-only FortiSIEM connector (SUDARE_FORTISIEM_*), server-wide.
    pub fortisiem: Option<sudare_egress::siem::FortiSiem>,
}

const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "change-me",
    "change_me",
    "changeit",
    "password",
    "passw0rd",
    "secret",
    "admin",
    "admin123",
    "admin@123",
    "example",
    "default",
    "test",
    "placeholder",
    "letmein",
    "todo",
    "xxx",
    "qwerty",
    "123456",
];

/// Common placeholder values, and anything that says "change me" / "replace" / "your_".
pub fn is_placeholder(v: &str) -> bool {
    let l = v.trim().to_ascii_lowercase();
    PLACEHOLDERS.contains(&l.as_str())
        || [
            "changeme",
            "change_me",
            "change-me",
            "replace",
            "your_",
            "your-",
            "<",
            "example",
        ]
        .iter()
        .any(|p| l.contains(p))
}

pub fn parse_secret_key(hex: &str) -> Result<[u8; 32], String> {
    let h = hex.trim();
    if is_placeholder(h) {
        return Err("SUDARE_SECRET_KEY is a placeholder; generate one with `sudare keygen`".into());
    }
    if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "SUDARE_SECRET_KEY must be 64 hex characters; generate one with `sudare keygen`".into(),
        );
    }
    let mut key = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    let distinct = key.iter().collect::<std::collections::HashSet<_>>().len();
    if distinct < 12 {
        return Err(
            "SUDARE_SECRET_KEY has too little entropy; generate one with `sudare keygen`".into(),
        );
    }
    Ok(key)
}

/// Admin bootstrap passwords: at least 12 characters and not a placeholder.
pub fn check_password(pw: &str) -> Result<(), String> {
    if pw.chars().count() < 12 {
        return Err("password must be at least 12 characters".into());
    }
    if is_placeholder(pw) {
        return Err("password is a placeholder".into());
    }
    Ok(())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let secret_key = Zeroizing::new(parse_secret_key(
            &get("SUDARE_SECRET_KEY")
                .ok_or("SUDARE_SECRET_KEY is not set; generate one with `sudare keygen`")?,
        )?);
        let bind: SocketAddr = get("SUDARE_BIND")
            .unwrap_or_else(|| "127.0.0.1:8080".into())
            .parse()
            .map_err(|e| format!("SUDARE_BIND: {e}"))?;
        let mode = match get("SUDARE_MODE").as_deref() {
            None | Some("single") => UserMode::Single,
            Some("multi") => UserMode::Multi,
            Some(other) => {
                return Err(format!(
                    "SUDARE_MODE must be single or multi, not {other:?}"
                ));
            }
        };
        let token = match get("SUDARE_TOKEN") {
            Some(t) if t.len() < 32 || is_placeholder(&t) => {
                return Err(
                    "SUDARE_TOKEN must be at least 32 characters and not a placeholder".into(),
                );
            }
            t => t.map(Zeroizing::new),
        };
        let allowed_hosts = match get("SUDARE_ALLOWED_HOSTS") {
            Some(h) => h
                .split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            None if bind.ip().is_loopback() => {
                let p = bind.port();
                vec![
                    format!("127.0.0.1:{p}"),
                    format!("localhost:{p}"),
                    format!("[::1]:{p}"),
                ]
            }
            None => {
                return Err(
                    "SUDARE_ALLOWED_HOSTS is required when binding to a non-loopback address"
                        .into(),
                );
            }
        };
        let data_dir = get("SUDARE_DATA_DIR")
            .map(PathBuf::from)
            .or_else(|| get("XDG_DATA_HOME").map(|d| PathBuf::from(d).join("sudare")))
            .or_else(|| get("HOME").map(|h| PathBuf::from(h).join(".local/share/sudare")))
            .ok_or("set SUDARE_DATA_DIR")?;
        let retention_days = match get("SUDARE_RETENTION_DAYS") {
            Some(d) => d
                .parse()
                .ok()
                .filter(|d| (1..=3650).contains(d))
                .ok_or("SUDARE_RETENTION_DAYS must be 1-3650")?,
            None => 30,
        };
        let num_ctx = match get("SUDARE_NUM_CTX") {
            Some(n) => n.parse().map_err(|_| "SUDARE_NUM_CTX must be a number")?,
            None => 16_384,
        };
        Ok(Self {
            bind,
            mode,
            data_dir,
            secret_key,
            token,
            admin_password: get("SUDARE_ADMIN_PASSWORD").map(Zeroizing::new),
            allowed_hosts,
            cookie_secure: matches!(get("SUDARE_COOKIE_SECURE").as_deref(), Some("true" | "1")),
            retention_days,
            policy: get("SUDARE_POLICY").map(PathBuf::from),
            ollama_url: get("SUDARE_OLLAMA_URL"),
            compat_url: get("SUDARE_OPENAI_COMPAT_URL"),
            compat_model: get("SUDARE_OPENAI_COMPAT_MODEL"),
            local_hosts: get("SUDARE_LOCAL_HOSTS")
                .map(|h| {
                    h.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            num_ctx,
            fortisiem: sudare_egress::siem::FortiSiem::from_lookup(&get)
                .map_err(|e| e.to_string())?,
        })
    }
}
