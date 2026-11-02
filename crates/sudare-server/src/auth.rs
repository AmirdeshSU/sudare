//! Sessions, CSRF, passwords and login throttling.

use crate::db::User;
use crate::secrets::{constant_time_eq, sha256_hex};
use crate::{ApiError, AppState};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, header};
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SESSION_COOKIE: &str = "sudare_session";
pub const CSRF_COOKIE: &str = "sudare_csrf";
pub const CSRF_HEADER: &str = "x-csrf-token";
pub const SESSION_SECS: i64 = 12 * 3600;
pub const LOCKOUT_FAILURES: i64 = 5;
pub const LOCKOUT_SECS: i64 = 15 * 60;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub fn hash_password(pw: &str) -> String {
    use argon2::password_hash::PasswordHasher;
    argon2::Argon2::default()
        .hash_password(pw.as_bytes())
        .expect("argon2 hashing")
        .to_string()
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    use argon2::password_hash::PasswordVerifier;
    use argon2::password_hash::phc::PasswordHash;
    PasswordHash::new(hash).is_ok_and(|h| {
        argon2::Argon2::default()
            .verify_password(pw.as_bytes(), &h)
            .is_ok()
    })
}

/// Spent on unknown usernames so a login takes the same time either way.
pub static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password("sudare-timing-equalizer"));

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

fn header(v: String) -> HeaderValue {
    HeaderValue::from_str(&v).expect("cookie value is ASCII")
}

pub fn session_cookies(token: &str, csrf: &str, secure: bool) -> [HeaderValue; 2] {
    let s = if secure { "; Secure" } else { "" };
    [
        header(format!(
            "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECS}{s}"
        )),
        header(format!(
            "{CSRF_COOKIE}={csrf}; Path=/; SameSite=Strict; Max-Age={SESSION_SECS}{s}"
        )),
    ]
}

pub fn clear_cookies(secure: bool) -> [HeaderValue; 2] {
    let s = if secure { "; Secure" } else { "" };
    [
        header(format!(
            "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{s}"
        )),
        header(format!(
            "{CSRF_COOKIE}=; Path=/; SameSite=Strict; Max-Age=0{s}"
        )),
    ]
}

pub fn is_safe_method(m: &Method) -> bool {
    matches!(*m, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// A logged-in request. State-changing requests must also carry the session's CSRF
/// token in `x-csrf-token` (the SPA reads it from the `sudare_csrf` cookie).
pub struct Session {
    pub user: User,
    pub token_hash: String,
}

impl Session {
    pub fn require_admin(&self) -> Result<(), ApiError> {
        if self.user.role == "admin" {
            Ok(())
        } else {
            Err(ApiError::new(403, "forbidden", "admin only"))
        }
    }
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, s: &AppState) -> Result<Self, ApiError> {
        let unauthorized = || ApiError::new(401, "unauthorized", "log in first");
        let token = cookie(&parts.headers, SESSION_COOKIE).ok_or_else(unauthorized)?;
        let token_hash = sha256_hex(token.as_bytes());
        let (user, csrf) = s.db.session(&token_hash, now())?.ok_or_else(unauthorized)?;
        if !is_safe_method(&parts.method) {
            let sent = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !constant_time_eq(sent, &csrf) {
                return Err(ApiError::new(403, "csrf", "missing or wrong CSRF token"));
            }
        }
        Ok(Session { user, token_hash })
    }
}
