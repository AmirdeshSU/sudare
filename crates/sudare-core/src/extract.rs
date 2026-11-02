//! Entity extractors. Each one records the byte span of every entity it finds; the
//! masker resolves overlaps. All regexes run in linear time (Rust `regex` crate).

use crate::parse::Parser;
use crate::types::{Entity, EntityType, Event, Source, Span};
use regex::Regex;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::LazyLock;

pub trait Extractor: Send + Sync {
    fn name(&self) -> &str;
    fn extract(&self, text: &str, events: &[Event], out: &mut Vec<Entity>);
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> =
            LazyLock::new(|| Regex::new($pat).expect(stringify!($name)));
    };
}

re!(
    IPV4,
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}"
);
re!(IPV6_CANDIDATE, r"(?i)[0-9a-f:]*:[0-9a-f:]*:[0-9a-f:.]*");
re!(URL, r#"(?i)\b(?:https?|ftps?|wss?)://[^\s"'<>`{}|\\^]+"#);
re!(
    EMAIL,
    r"(?i)\b[a-z0-9._%+-]{1,64}@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"
);
re!(
    FQDN,
    r"(?i)\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,22}[a-z0-9]\b"
);
re!(
    DOMAIN_USER,
    r"\b([A-Za-z][A-Za-z0-9_.-]{0,62})\\{1,2}([A-Za-z0-9_.$-]{1,64})"
);
re!(SHA256, r"\b[a-fA-F0-9]{64}\b");
re!(SHA1, r"\b[a-fA-F0-9]{40}\b");
re!(MD5, r"\b[a-fA-F0-9]{32}\b");
re!(
    MAC,
    r"(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b|\b[0-9a-f]{2}(?:-[0-9a-f]{2}){5}\b|\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b"
);
re!(CVE, r"(?i)\bCVE-\d{4}-\d{4,7}\b");
re!(
    WIN_PATH,
    r#"(?i)\b[a-z]:\\{1,2}(?:[^\\/:*?"<>|\s]+\\{1,2})*[^\\/:*?"<>|\s]*"#
);
re!(UNC_HOST, r"\\{2,4}([A-Za-z0-9][A-Za-z0-9.-]{0,253})\\");
re!(
    UNIX_PATH,
    r#"(?:^|[\s"'=(,\[])(/(?:[A-Za-z0-9._~+@-]+/)+[A-Za-z0-9._~+@-]*)"#
);
re!(
    USER_IN_PATH,
    r"(?i)(?:\\{1,2}Users\\{1,2}|/home/|/Users/)([A-Za-z0-9._$-]{1,64})"
);
re!(PROCESS, r"(?i)\b[\w-]{1,64}\.exe\b");
re!(
    SID,
    r"\bS-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}(?:-\d{1,10})?\b"
);
re!(
    HASH_CONTEXT,
    r"(?i)(?:md5|sha-?1|sha-?256|hash|checksum|digest|ioc)"
);
re!(
    KV,
    r#"(?i)(?:^|[\s,;{(\["])([a-z_][\w.-]{0,63})"?\s*[=:]\s*("[^"\n]{0,512}"|'[^'\n]{0,512}'|[^\s,;"'}\])]{1,512})"#
);

re!(
    SECRET_KV,
    r#"(?i)\b(?:secret[_-]?access[_-]?key|client[_-]?secret|private[_-]?key|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|auth[_-]?token|session[_-]?token|passphrase|password|passwd|secret|token)"?\s*[=:]\s*("[^"\n]{1,512}"|'[^'\n]{1,512}'|[^\s,;&"'}]{1,512})"#
);
re!(BEARER, r"(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})");
re!(AWS_KEY, r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b");
re!(
    PRIVATE_KEY,
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,8192}?-----END [A-Z ]*PRIVATE KEY-----"
);
re!(
    JWT,
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
);
re!(
    URL_PASSWORD,
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:([^\s/@]+)@"
);
re!(
    VENDOR_TOKEN,
    r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})\b"
);

/// Real TLDs worth matching. Two-letter labels are accepted unless they're common
/// file extensions; `.zip` and `.mov` are left out on purpose.
const TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "info",
    "biz",
    "io",
    "ai",
    "app",
    "dev",
    "cloud",
    "xyz",
    "top",
    "site",
    "online",
    "tech",
    "store",
    "shop",
    "tv",
    "pro",
    "name",
    "mobi",
    "asia",
    "tel",
    "travel",
    "jobs",
    "museum",
    "aero",
    "coop",
    "cat",
    "post",
    "arpa",
    "onion",
    "page",
    "blog",
    "live",
    "news",
    "email",
    "club",
    "link",
    "click",
    "win",
    "bid",
    "loan",
    "work",
    "today",
    "world",
    "global",
    "space",
    "website",
    "digital",
    "network",
    "systems",
    "solutions",
    "services",
    "agency",
    "company",
    "center",
    "life",
    "group",
    "zone",
    "tools",
    "software",
    "host",
    "support",
    "bank",
    "finance",
    "capital",
    "media",
    "social",
    "icu",
    "buzz",
    "rest",
    "fun",
    "monster",
    "cyou",
    "sbs",
    "lol",
    "quest",
    "beauty",
    "hair",
    "skin",
    "makeup",
    "bond",
    "cfd",
    "autos",
    "boats",
    "homes",
    "motorcycles",
    "yachts",
    "local",
    "internal",
    "lan",
    "localdomain",
    "intranet",
    "corp",
    "private",
    "localhost",
];
const FILE_EXT2: &[&str] = &[
    "js", "py", "sh", "ps", "db", "gz", "xz", "bz", "rb", "pl", "go", "cs", "md", "rs", "so", "ko",
    "el", "hs", "ts", "cc", "mo", "po", "ml", "pm", "vb", "7z",
];
const PLACEHOLDERS: &[&str] = &[
    "",
    "-",
    "--",
    "n/a",
    "na",
    "null",
    "none",
    "unknown",
    "nil",
    "undefined",
    "0",
    "localhost",
    "*",
    "?",
];
/// Built-in principals that identify nobody.
const WELL_KNOWN_ACCOUNTS: &[&str] = &[
    "system",
    "local service",
    "network service",
    "anonymous logon",
    "root",
    "daemon",
    "nobody",
    "www-data",
    "nt authority\\system",
    "dwm-1",
    "umfd-0",
    "umfd-1",
];
const NON_DOMAINS: &[&str] = &[
    "authority",
    "builtin",
    "service",
    "hklm",
    "hkcu",
    "hkcr",
    "hku",
    "hkey_local_machine",
    "hkey_current_user",
    "hkey_users",
    "hkey_classes_root",
];
const NON_USER_DIRS: &[&str] = &["public", "default", "all users", "default user", "shared"];

fn char_before(text: &str, i: usize) -> Option<char> {
    text[..i].chars().next_back()
}
fn char_after(text: &str, i: usize) -> Option<char> {
    text[i..].chars().next()
}
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `value` occurs at `s..e` as a whole token: no word character glued to either end.
pub(crate) fn whole_word(text: &str, s: usize, e: usize) -> bool {
    let glued_before = text[s..e].starts_with(is_word)
        && char_before(text, s).is_some_and(|c| is_word(c) || c == '-');
    let glued_after =
        text[..e].ends_with(is_word) && char_after(text, e).is_some_and(|c| is_word(c) || c == '-');
    !glued_before && !glued_after
}

/// Namespace URIs in XML (`xmlns="..."`) are structure, not data.
fn in_xmlns(text: &str, s: usize) -> bool {
    let head = &text[..s];
    let Some(head) = head.strip_suffix('"').or_else(|| head.strip_suffix('\'')) else {
        return false;
    };
    let Some(head) = head.strip_suffix('=') else {
        return false;
    };
    let word = head
        .rsplit(|c: char| c.is_whitespace() || c == '<')
        .next()
        .unwrap_or("");
    word == "xmlns" || word.starts_with("xmlns:")
}

fn valid_tld(fqdn: &str) -> bool {
    let tld = fqdn.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    if tld.len() == 2 {
        return tld.chars().all(|c| c.is_ascii_alphabetic()) && !FILE_EXT2.contains(&tld.as_str());
    }
    TLDS.contains(&tld.as_str())
}

fn hash_kind(v: &str) -> Option<EntityType> {
    if !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    match v.len() {
        32 => Some(EntityType::Md5),
        40 => Some(EntityType::Sha1),
        64 => Some(EntityType::Sha256),
        _ => None,
    }
}

/// Check a typed field value and pick its concrete entity type.
pub(crate) fn refine(t: EntityType, v: &str) -> Option<EntityType> {
    use EntityType::*;
    let v = v.trim();
    if v.len() > 2048 || PLACEHOLDERS.contains(&v.to_ascii_lowercase().as_str()) {
        return None;
    }
    let is_ip = v.trim_matches(['[', ']']).parse::<IpAddr>().is_ok();
    match t {
        Ip => is_ip.then_some(Ip),
        Hostname | Fqdn | Username if is_ip => Some(Ip),
        Hostname | Fqdn => {
            let ok = v
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '$'));
            ok.then(|| {
                if v.trim_end_matches('.').contains('.') {
                    Fqdn
                } else {
                    Hostname
                }
            })
        }
        Username => {
            if WELL_KNOWN_ACCOUNTS.contains(&v.to_ascii_lowercase().as_str()) {
                None
            } else if EMAIL.find(v).is_some_and(|m| m.len() == v.len()) {
                Some(Email)
            } else {
                Some(Username)
            }
        }
        Email => EMAIL.is_match(v).then_some(Email),
        Url => v.contains("://").then_some(Url),
        Md5 | Sha1 | Sha256 => hash_kind(v),
        Mac => MAC
            .find(v)
            .is_some_and(|m| m.len() == v.len())
            .then_some(Mac),
        other => Some(other),
    }
}

/// Format-independent patterns: addresses, URLs, emails, domains, hashes, paths, ...
pub struct RegexExtractor;

impl Extractor for RegexExtractor {
    fn name(&self) -> &str {
        "regex"
    }

    fn extract(&self, text: &str, _: &[Event], out: &mut Vec<Entity>) {
        use EntityType::*;
        let start = out.len();
        let mut skip: Vec<Span> = Vec::new();
        let push = |out: &mut Vec<Entity>, kind: EntityType, s: usize, e: usize| {
            out.push(Entity::new(kind, text, Span::new(s, e), Source::Regex));
        };

        for m in IPV4.find_iter(text) {
            let before = char_before(text, m.start());
            let after = text[m.end()..].chars().take(2).collect::<Vec<_>>();
            let bad_before = before.is_some_and(|c| c.is_ascii_digit() || c == '.');
            let bad_after = match after.as_slice() {
                [c, ..] if c.is_alphanumeric() => true,
                ['.', d, ..] if d.is_ascii_digit() => true,
                _ => false,
            };
            if !bad_before && !bad_after {
                push(out, Ip, m.start(), m.end());
            }
        }

        for m in IPV6_CANDIDATE.find_iter(text) {
            let mut cand = m.as_str();
            if cand.ends_with(':') && !cand.ends_with("::") {
                cand = &cand[..cand.len() - 1];
            }
            let (s, e) = (m.start(), m.start() + cand.len());
            let hex_digits = cand.chars().filter(|c| c.is_ascii_hexdigit()).count();
            let glued = char_before(text, s).is_some_and(|c| is_word(c) || c == '.')
                || char_after(text, e).is_some_and(is_word);
            if hex_digits >= 1 && cand.len() >= 3 && !glued && cand.parse::<Ipv6Addr>().is_ok() {
                push(out, Ip, s, e);
            }
        }

        for m in URL.find_iter(text) {
            let trimmed = m
                .as_str()
                .trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}', '>', '\'', '"']);
            let (s, e) = (m.start(), m.start() + trimmed.len());
            if in_xmlns(text, s) {
                skip.push(Span::new(s, e));
                continue;
            }
            push(out, Url, s, e);
        }

        for m in EMAIL.find_iter(text) {
            push(out, Email, m.start(), m.end());
        }

        for m in FQDN.find_iter(text) {
            let after_paren = char_after(text, m.end()) == Some('(');
            let in_path = char_before(text, m.start()).is_some_and(|c| c == '\\');
            if valid_tld(m.as_str()) && !after_paren && !in_path {
                push(out, Fqdn, m.start(), m.end());
            }
        }

        for c in DOMAIN_USER.captures_iter(text) {
            let (Some(all), Some(domain)) = (c.get(0), c.get(1)) else {
                continue;
            };
            let bad_before =
                char_before(text, all.start()).is_some_and(|c| matches!(c, '\\' | ':' | '/' | '.'));
            let bad_after = char_after(text, all.end()).is_some_and(|c| c == '\\');
            if !bad_before
                && !bad_after
                && !NON_DOMAINS.contains(&domain.as_str().to_ascii_lowercase().as_str())
            {
                push(out, Username, all.start(), all.end());
            }
        }

        for (re, kind) in [(&*SHA256, Sha256), (&*SHA1, Sha1), (&*MD5, Md5)] {
            for m in re.find_iter(text) {
                // Bare hex strings may be session IDs; only those with hash context nearby
                // (or from a hash-typed field) become threat-intel lookups.
                let line_start = text[..m.start()].rfind('\n').map_or(0, |i| i + 1);
                let mut ctx_start = m.start().saturating_sub(40).max(line_start);
                while !text.is_char_boundary(ctx_start) {
                    ctx_start += 1;
                }
                let source = if HASH_CONTEXT.is_match(&text[ctx_start..m.start()]) {
                    Source::KeyValue("hash".into())
                } else {
                    Source::Regex
                };
                out.push(Entity::new(
                    kind.clone(),
                    text,
                    Span::new(m.start(), m.end()),
                    source,
                ));
            }
        }

        for m in MAC.find_iter(text) {
            push(out, Mac, m.start(), m.end());
        }
        for m in CVE.find_iter(text) {
            push(out, Cve, m.start(), m.end());
        }
        for m in WIN_PATH.find_iter(text) {
            push(out, FilePath, m.start(), m.end());
        }
        for c in UNC_HOST.captures_iter(text) {
            let (Some(all), Some(host)) = (c.get(0), c.get(1)) else {
                continue;
            };
            let starts_field = char_before(text, all.start()).is_none_or(|c| {
                c.is_whitespace() || matches!(c, '"' | '\'' | '=' | '(' | ',' | '>' | '[')
            });
            if starts_field {
                let kind = if host.as_str().contains('.') {
                    Fqdn
                } else {
                    Hostname
                };
                push(out, kind, host.start(), host.end());
            }
        }
        for c in UNIX_PATH.captures_iter(text) {
            if let Some(p) = c.get(1) {
                push(out, FilePath, p.start(), p.end());
            }
        }
        for c in USER_IN_PATH.captures_iter(text) {
            let Some(u) = c.get(1) else { continue };
            let ends_ok = char_after(text, u.end())
                .is_none_or(|c| matches!(c, '\\' | '/' | '"' | '\'') || c.is_whitespace());
            if ends_ok && !NON_USER_DIRS.contains(&u.as_str().to_ascii_lowercase().as_str()) {
                push(out, Username, u.start(), u.end());
            }
        }
        for m in PROCESS.find_iter(text) {
            push(out, Process, m.start(), m.end());
        }
        for m in SID.find_iter(text) {
            push(out, Custom("SID".into()), m.start(), m.end());
        }

        if !skip.is_empty() {
            let mut i = start;
            while i < out.len() {
                if skip.iter().any(|s| s.contains(&out[i].span)) {
                    out.remove(i);
                } else {
                    i += 1;
                }
            }
        }
    }
}

/// Credentials and tokens. Always masked, in every mode.
pub struct SecretExtractor;

impl Extractor for SecretExtractor {
    fn name(&self) -> &str {
        "secrets"
    }

    fn extract(&self, text: &str, _: &[Event], out: &mut Vec<Entity>) {
        let secret = |s: usize, e: usize| {
            Entity::new(EntityType::Secret, text, Span::new(s, e), Source::Regex)
        };
        for re in [&*SECRET_KV, &*BEARER, &*URL_PASSWORD] {
            for c in re.captures_iter(text) {
                let Some(v) = c.get(1) else { continue };
                let (mut s, mut e) = (v.start(), v.end());
                let raw = v.as_str();
                if raw.len() >= 2 && (raw.starts_with('"') || raw.starts_with('\'')) {
                    s += 1;
                    e -= 1;
                }
                let val = &text[s..e];
                if !val.is_empty() && !val.chars().all(|c| c == '*' || c == 'x' || c == 'X') {
                    out.push(secret(s, e));
                }
            }
        }
        for re in [&*AWS_KEY, &*PRIVATE_KEY, &*JWT, &*VENDOR_TOKEN] {
            for m in re.find_iter(text) {
                out.push(secret(m.start(), m.end()));
            }
        }
    }
}

/// Values of fields the parser knows the type of, plus `key=value` pairs anywhere.
pub struct FieldExtractor<'a> {
    pub parser: &'a dyn Parser,
}

impl Extractor for FieldExtractor<'_> {
    fn name(&self) -> &str {
        "fields"
    }

    fn extract(&self, text: &str, events: &[Event], out: &mut Vec<Entity>) {
        for ev in events {
            let base = ev.span.start;
            let slice = &text[ev.span.start..ev.span.end];
            for (key, value) in &ev.fields {
                let Some(kind) = self.parser.field_type(key).and_then(|t| refine(t, value)) else {
                    continue;
                };
                let value = value.trim();
                // JSON and CEF exports double backslashes in DOMAIN\user and paths.
                let escaped = value.replace('\\', "\\\\");
                for needle in [value, escaped.as_str()] {
                    let mut found = false;
                    for (i, _) in slice.match_indices(needle) {
                        let (s, e) = (base + i, base + i + needle.len());
                        if whole_word(text, s, e) {
                            out.push(Entity::new(
                                kind.clone(),
                                text,
                                Span::new(s, e),
                                Source::Field(key.clone()),
                            ));
                            found = true;
                        }
                    }
                    if found || !value.contains('\\') {
                        break;
                    }
                }
            }
        }

        // Quoted values are scanned again from the inside: a JSON field such as
        // "rawMessage": "... user=jdoe ..." holds pairs of its own.
        let mut pos = 0;
        while let Some(c) = KV.captures_at(text, pos) {
            let (Some(all), Some(k), Some(v)) = (c.get(0), c.get(1), c.get(2)) else {
                break;
            };
            let quoted = v.as_str().len() >= 2
                && (v.as_str().starts_with('"') || v.as_str().starts_with('\''));
            pos = if quoted {
                v.start() + 1
            } else {
                all.end().max(pos + 1)
            };
            let Some(t) = self.parser.field_type(k.as_str()) else {
                continue;
            };
            let (mut s, mut e) = (v.start(), v.end());
            if quoted {
                s += 1;
                e -= 1;
            }
            let val = &text[s..e];
            // The regex extractor already covers IPs and MACs wherever they appear.
            let Some(kind) =
                refine(t, val).filter(|k| !matches!(k, EntityType::Ip | EntityType::Mac))
            else {
                continue;
            };
            let trimmed = val.trim();
            let s = s + (val.len() - val.trim_start().len());
            let e = s + trimmed.len();
            if s < e {
                out.push(Entity::new(
                    kind,
                    text,
                    Span::new(s, e),
                    Source::KeyValue(k.as_str().to_string()),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Raw;

    fn kinds(text: &str) -> Vec<(EntityType, String)> {
        let mut out = Vec::new();
        RegexExtractor.extract(text, &[], &mut out);
        SecretExtractor.extract(text, &[], &mut out);
        FieldExtractor { parser: &Raw }.extract(text, &[], &mut out);
        out.into_iter().map(|e| (e.kind, e.value)).collect()
    }

    fn has(v: &[(EntityType, String)], k: EntityType, s: &str) -> bool {
        v.iter().any(|(kk, vv)| *kk == k && vv == s)
    }

    #[test]
    fn the_masking_py_regressions() {
        // The old regex masker tagged timestamps and MACs as IPv6 and missed users/hosts.
        let v = kinds(
            "Oct 29 14:11:40 fw01 login failed user=jdoe from 10.1.2.3 to http://10.9.9.9/admin mac aa:bb:cc:dd:ee:ff host ws-17.corp.example.com",
        );
        assert!(
            !v.iter()
                .any(|(k, s)| *k == EntityType::Ip && s.contains("14:11"))
        );
        assert!(
            !v.iter()
                .any(|(k, s)| *k == EntityType::Ip && s.contains("aa:bb"))
        );
        assert!(has(&v, EntityType::Mac, "aa:bb:cc:dd:ee:ff"));
        assert!(has(&v, EntityType::Username, "jdoe"));
        assert!(has(&v, EntityType::Ip, "10.1.2.3"));
        assert!(has(&v, EntityType::Url, "http://10.9.9.9/admin"));
        assert!(has(&v, EntityType::Fqdn, "ws-17.corp.example.com"));
    }

    #[test]
    fn ips_versions_and_v6() {
        let v = kinds("ver 1.2.3.4.5 ip 2001:db8::1 mapped ::ffff:192.0.2.1 std::vector");
        assert!(!has(&v, EntityType::Ip, "1.2.3.4"));
        assert!(has(&v, EntityType::Ip, "2001:db8::1"));
        assert!(has(&v, EntityType::Ip, "::ffff:192.0.2.1"));
        assert!(
            !v.iter()
                .any(|(k, s)| *k == EntityType::Ip && s.contains("::v"))
        );
    }

    #[test]
    fn domains_skip_files_and_namespaces() {
        let v = kinds(
            "cmd.exe report.pdf payroll.xlsx evil.example.org <E xmlns=\"http://schemas.example.com/x\"/>",
        );
        assert!(has(&v, EntityType::Fqdn, "evil.example.org"));
        assert!(
            !v.iter()
                .any(|(_, s)| s.contains("report.pdf") || s.contains("payroll"))
        );
        assert!(!v.iter().any(|(_, s)| s.contains("schemas.example.com")));
        assert!(has(&v, EntityType::Process, "cmd.exe"));
    }

    #[test]
    fn domain_users_not_paths() {
        let v = kinds(
            r"logon CORP\mlee path C:\Windows\System32\cmd.exe key HKLM\Software NT AUTHORITY\SYSTEM",
        );
        assert!(has(&v, EntityType::Username, r"CORP\mlee"));
        assert!(!v.iter().any(|(k, s)| *k == EntityType::Username
            && (s.contains("System32") || s.contains("Software") || s.contains("SYSTEM"))));
        assert!(has(
            &v,
            EntityType::FilePath,
            r"C:\Windows\System32\cmd.exe"
        ));
    }

    #[test]
    fn secrets() {
        let v = kinds(
            r#"password=hunter2 "secretAccessKey":"abc/def" Authorization: Bearer abcdefghijkl AKIAABCDEFGHIJKLMNOP PWD=/home/x"#,
        );
        assert!(has(&v, EntityType::Secret, "hunter2"));
        assert!(has(&v, EntityType::Secret, "abc/def"));
        assert!(has(&v, EntityType::Secret, "abcdefghijkl"));
        assert!(has(&v, EntityType::Secret, "AKIAABCDEFGHIJKLMNOP"));
        assert!(!has(&v, EntityType::Secret, "/home/x"));
    }

    #[test]
    fn pairs_inside_quoted_values() {
        let v = kinds(
            r#"{"rawMessage": "<13>Oct 29 18:00:00 dc02 Security: failed user=hgupta src=x", "host": "fw9"}"#,
        );
        assert!(has(&v, EntityType::Username, "hgupta"));
        assert!(has(&v, EntityType::Hostname, "fw9"));
    }

    #[test]
    fn hash_context_controls_lookup_eligibility() {
        let h = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        let mut out = Vec::new();
        RegexExtractor.extract(&format!("sha256={h} session {}", &h[..32]), &[], &mut out);
        let sha = out.iter().find(|e| e.kind == EntityType::Sha256).unwrap();
        assert!(matches!(sha.source, Source::KeyValue(_)));
        let md5 = out.iter().find(|e| e.kind == EntityType::Md5).unwrap();
        assert!(matches!(md5.source, Source::Regex));
    }
}
