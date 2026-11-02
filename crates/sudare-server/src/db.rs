//! SQLite storage. One connection behind a mutex: every query is small, and the
//! analysis work happens outside the lock.
// ponytail: single connection, move to a pool if concurrent users make it a bottleneck.

use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
PRAGMA secure_delete = ON;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_failures (
    key TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    first_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    sealed BLOB NOT NULL,
    hint TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, name)
);
CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    masked_input TEXT NOT NULL,
    masked_output TEXT NOT NULL,
    report TEXT NOT NULL,
    sealed_session BLOB NOT NULL,
    verdict TEXT,
    severity TEXT,
    summary TEXT
);
CREATE INDEX IF NOT EXISTS analyses_user ON analyses (user_id, created_at);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub role: String,
}

pub struct AnalysisRow {
    pub id: String,
    pub created_at: i64,
    pub masked_input: String,
    pub masked_output: String,
    pub report: String,
    pub sealed_session: Vec<u8>,
}

#[derive(Serialize)]
pub struct AnalysisSummary {
    pub id: String,
    pub created_at: i64,
    pub verdict: Option<String>,
    pub severity: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("database: {0}")]
pub struct DbError(#[from] rusqlite::Error);

pub struct Db {
    conn: Mutex<Connection>,
}

type R<T> = Result<T, DbError>;

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let conn = Connection::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> R<T> {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        Ok(f(&conn)?)
    }

    // users

    pub fn user_count(&self) -> R<i64> {
        self.with(|c| c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)))
    }

    pub fn create_user(&self, username: &str, password_hash: &str, role: &str, now: i64) -> R<i64> {
        self.with(|c| {
            c.execute(
                "INSERT INTO users (username, password_hash, role, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![username, password_hash, role, now],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    /// (user, password hash). Usernames are case-insensitive.
    pub fn find_user(&self, username: &str) -> R<Option<(User, String)>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, username, role, password_hash FROM users WHERE username = ?1",
                [username],
                |r| {
                    Ok((
                        User {
                            id: r.get(0)?,
                            username: r.get(1)?,
                            role: r.get(2)?,
                        },
                        r.get(3)?,
                    ))
                },
            )
            .optional()
        })
    }

    pub fn list_users(&self) -> R<Vec<User>> {
        self.with(|c| {
            let mut s = c.prepare("SELECT id, username, role FROM users ORDER BY username")?;
            s.query_map([], |r| {
                Ok(User {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    role: r.get(2)?,
                })
            })?
            .collect()
        })
    }

    pub fn delete_user(&self, id: i64) -> R<bool> {
        self.with(|c| Ok(c.execute("DELETE FROM users WHERE id = ?1", [id])? > 0))
    }

    // sessions

    pub fn create_session(
        &self,
        token_hash: &str,
        user_id: i64,
        csrf: &str,
        expires_at: i64,
    ) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![token_hash, user_id, csrf, expires_at],
            )
            .map(|_| ())
        })
    }

    /// (user, csrf) for a live session.
    pub fn session(&self, token_hash: &str, now: i64) -> R<Option<(User, String)>> {
        self.with(|c| {
            c.query_row(
                "SELECT u.id, u.username, u.role, s.csrf FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ?1 AND s.expires_at > ?2",
                params![token_hash, now],
                |r| Ok((User { id: r.get(0)?, username: r.get(1)?, role: r.get(2)? }, r.get(3)?)),
            )
            .optional()
        })
    }

    pub fn delete_session(&self, token_hash: &str) -> R<()> {
        self.with(|c| {
            c.execute("DELETE FROM sessions WHERE token_hash = ?1", [token_hash])
                .map(|_| ())
        })
    }

    // login throttling: 5 failures per key per 15 minutes

    pub fn recent_failures(&self, key: &str, since: i64) -> R<i64> {
        self.with(|c| {
            Ok(c.query_row(
                "SELECT count FROM login_failures WHERE key = ?1 AND first_at > ?2",
                params![key, since],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0))
        })
    }

    pub fn record_failure(&self, key: &str, now: i64, since: i64) -> R<()> {
        self.with(|c| {
            c.execute(
                "DELETE FROM login_failures WHERE key = ?1 AND first_at <= ?2",
                params![key, since],
            )?;
            c.execute(
                "INSERT INTO login_failures (key, count, first_at) VALUES (?1, 1, ?2)
                 ON CONFLICT(key) DO UPDATE SET count = count + 1",
                params![key, now],
            )
            .map(|_| ())
        })
    }

    pub fn clear_failures(&self, key: &str) -> R<()> {
        self.with(|c| {
            c.execute("DELETE FROM login_failures WHERE key = ?1", [key])
                .map(|_| ())
        })
    }

    // API keys (sealed)

    pub fn put_key(&self, user_id: i64, name: &str, sealed: &[u8], hint: &str, now: i64) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO api_keys (user_id, name, sealed, hint, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(user_id, name) DO UPDATE SET sealed = ?3, hint = ?4, updated_at = ?5",
                params![user_id, name, sealed, hint, now],
            )
            .map(|_| ())
        })
    }

    pub fn get_key(&self, user_id: i64, name: &str) -> R<Option<Vec<u8>>> {
        self.with(|c| {
            c.query_row(
                "SELECT sealed FROM api_keys WHERE user_id = ?1 AND name = ?2",
                params![user_id, name],
                |r| r.get(0),
            )
            .optional()
        })
    }

    /// (name, hint, updated_at). Never the key.
    pub fn list_keys(&self, user_id: i64) -> R<Vec<(String, String, i64)>> {
        self.with(|c| {
            let mut s = c.prepare(
                "SELECT name, hint, updated_at FROM api_keys WHERE user_id = ?1 ORDER BY name",
            )?;
            s.query_map([user_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect()
        })
    }

    pub fn delete_key(&self, user_id: i64, name: &str) -> R<bool> {
        self.with(|c| {
            Ok(c.execute(
                "DELETE FROM api_keys WHERE user_id = ?1 AND name = ?2",
                params![user_id, name],
            )? > 0)
        })
    }

    // analyses

    #[allow(clippy::too_many_arguments)]
    pub fn insert_analysis(
        &self,
        id: &str,
        user_id: i64,
        now: i64,
        masked_input: &str,
        masked_output: &str,
        report: &str,
        sealed: &[u8],
        verdict: Option<&str>,
        severity: Option<&str>,
        summary: Option<&str>,
    ) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO analyses (id, user_id, created_at, masked_input, masked_output, report, sealed_session, verdict, severity, summary)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![id, user_id, now, masked_input, masked_output, report, sealed, verdict, severity, summary],
            )
            .map(|_| ())
        })
    }

    pub fn list_analyses(&self, user_id: i64) -> R<Vec<AnalysisSummary>> {
        self.with(|c| {
            let mut s = c.prepare(
                "SELECT id, created_at, verdict, severity, summary FROM analyses WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 500",
            )?;
            s.query_map([user_id], |r| {
                Ok(AnalysisSummary {
                    id: r.get(0)?,
                    created_at: r.get(1)?,
                    verdict: r.get(2)?,
                    severity: r.get(3)?,
                    summary: r.get(4)?,
                })
            })?
            .collect()
        })
    }

    pub fn get_analysis(&self, user_id: i64, id: &str) -> R<Option<AnalysisRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT id, created_at, masked_input, masked_output, report, sealed_session FROM analyses WHERE user_id = ?1 AND id = ?2",
                params![user_id, id],
                |r| {
                    Ok(AnalysisRow {
                        id: r.get(0)?,
                        created_at: r.get(1)?,
                        masked_input: r.get(2)?,
                        masked_output: r.get(3)?,
                        report: r.get(4)?,
                        sealed_session: r.get(5)?,
                    })
                },
            )
            .optional()
        })
    }

    pub fn update_session(&self, user_id: i64, id: &str, sealed: &[u8]) -> R<()> {
        self.with(|c| {
            c.execute(
                "UPDATE analyses SET sealed_session = ?3 WHERE user_id = ?1 AND id = ?2",
                params![user_id, id, sealed],
            )
            .map(|_| ())
        })
    }

    /// Removes the masked input, the result and the sealed map together.
    pub fn delete_analysis(&self, user_id: i64, id: &str) -> R<bool> {
        self.with(|c| {
            Ok(c.execute(
                "DELETE FROM analyses WHERE user_id = ?1 AND id = ?2",
                params![user_id, id],
            )? > 0)
        })
    }

    /// Retention, expired sessions and stale throttling rows.
    pub fn purge(&self, analyses_before: i64, now: i64) -> R<usize> {
        self.with(|c| {
            let n = c.execute(
                "DELETE FROM analyses WHERE created_at < ?1",
                [analyses_before],
            )?;
            c.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])?;
            c.execute(
                "DELETE FROM login_failures WHERE first_at <= ?1",
                [now - 15 * 60],
            )?;
            Ok(n)
        })
    }

    pub fn setting(&self, key: &str) -> R<Option<String>> {
        self.with(|c| {
            c.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| {
                r.get(0)
            })
            .optional()
        })
    }

    pub fn set_setting(&self, key: &str, value: &str) -> R<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = ?2",
                params![key, value],
            )
            .map(|_| ())
        })
    }

    #[doc(hidden)]
    pub fn raw_sealed_sessions(&self) -> R<Vec<Vec<u8>>> {
        self.with(|c| {
            let mut s = c.prepare("SELECT sealed_session FROM analyses")?;
            s.query_map([], |r| r.get(0))?.collect()
        })
    }

    #[doc(hidden)]
    pub fn backdate_analyses(&self, created_at: i64) -> R<()> {
        self.with(|c| {
            c.execute("UPDATE analyses SET created_at = ?1", [created_at])
                .map(|_| ())
        })
    }
}
