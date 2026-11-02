//! On-disk threat-intel cache (SQLite). Holds public indicators and provider answers
//! only. File mode 0600.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sudare_core::PublicIndicator;
use sudare_core::report::EnrichmentResult;

pub struct Cache {
    conn: Mutex<rusqlite::Connection>,
    ttl: Duration,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn kind(ind: &PublicIndicator) -> String {
    serde_json::to_value(ind.kind())
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

impl Cache {
    /// `$SUDARE_CACHE_DIR`, else `$XDG_CACHE_HOME/sudare`, else `~/.cache/sudare`.
    pub fn default_path() -> Option<PathBuf> {
        let dir = std::env::var_os("SUDARE_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(|d| PathBuf::from(d).join("sudare")))
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache/sudare")))?;
        Some(dir.join("ti-cache.sqlite"))
    }

    pub fn open(path: &Path, ttl: Duration) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| format!("cache dir {}: {e}", dir.display()))?;
        }
        let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Self::init(conn, ttl)
    }

    pub fn in_memory(ttl: Duration) -> Self {
        Self::init(
            rusqlite::Connection::open_in_memory().expect("in-memory SQLite"),
            ttl,
        )
        .expect("schema")
    }

    fn init(conn: rusqlite::Connection, ttl: Duration) -> Result<Self, String> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ti (
                provider TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
                at INTEGER NOT NULL, result TEXT NOT NULL,
                PRIMARY KEY (provider, kind, value));",
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
            ttl,
        })
    }

    pub fn get(&self, provider: &str, ind: &PublicIndicator) -> Option<EnrichmentResult> {
        let conn = self.conn.lock().ok()?;
        let (at, json): (i64, String) = conn
            .query_row(
                "SELECT at, result FROM ti WHERE provider = ?1 AND kind = ?2 AND value = ?3",
                (provider, kind(ind), ind.value()),
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok()?;
        if now() - at > self.ttl.as_secs() as i64 {
            return None;
        }
        let mut r: EnrichmentResult = serde_json::from_str(&json).ok()?;
        r.cached = true;
        Some(r)
    }

    pub fn put(&self, provider: &str, ind: &PublicIndicator, r: &EnrichmentResult) {
        let (Ok(conn), Ok(json)) = (self.conn.lock(), serde_json::to_string(r)) else {
            return;
        };
        let _ = conn.execute(
            "INSERT OR REPLACE INTO ti (provider, kind, value, at, result) VALUES (?1, ?2, ?3, ?4, ?5)",
            (provider, kind(ind), ind.value(), now(), json),
        );
    }
}
