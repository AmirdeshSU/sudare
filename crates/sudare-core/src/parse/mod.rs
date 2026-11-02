//! Parser registry: auto-detection plus manual override by name.
//!
//! JSON-shaped vendor formats are added as TOML mappings (see `mappings/`) rather than
//! Rust code; `CONTRIBUTING.md` explains both routes.

mod cef;
mod json;
mod syslog;
mod windows;

pub use json::{Mapping, MappingError};
#[cfg(feature = "evtx")]
pub use windows::evtx_to_xml;
pub use windows::is_evtx;

use crate::types::{EntityType, Event, Span};
use indexmap::IndexMap;
use regex::Regex;
use std::sync::LazyLock;

pub trait Parser: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    /// 0.0 (not this format) ..= 1.0 (certain), judged on the first 64 KiB.
    fn detect(&self, sample: &str) -> f32;
    /// Never panics. Records it can't read come back with `error` set.
    fn parse(&self, text: &str) -> Vec<Event>;
    /// Entity type of a field's value, if the field is known to hold one.
    fn field_type(&self, field: &str) -> Option<EntityType> {
        guess_field_type(field)
    }
    /// Fields naming the log source's own assets; their domains are learned as internal.
    fn self_fields(&self) -> Vec<String> {
        Vec::new()
    }
    /// Event type, used to sample rare types first when input exceeds the budget.
    fn group_key(&self, event: &Event) -> Option<String>;
}

pub struct Registry {
    parsers: Vec<Box<dyn Parser>>,
}

impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl Registry {
    pub fn builtin() -> Self {
        let mut parsers: Vec<Box<dyn Parser>> = json::BUILTIN_MAPPINGS
            .iter()
            .map(|m| {
                Box::new(json::MappedParser::from_toml(m).expect("built-in mapping is valid"))
                    as Box<dyn Parser>
            })
            .collect();
        parsers.push(Box::new(cef::Cef));
        parsers.push(Box::new(cef::Leef));
        parsers.push(Box::new(windows::WinXml));
        parsers.push(Box::new(syslog::Syslog5424));
        parsers.push(Box::new(syslog::Syslog3164));
        parsers.push(Box::new(json::Ndjson));
        parsers.push(Box::new(json::Json));
        parsers.push(Box::new(Raw));
        Self { parsers }
    }

    /// Add a TOML mapping; it takes priority over built-ins with the same score.
    pub fn add_mapping(&mut self, toml: &str) -> Result<(), MappingError> {
        let p = json::MappedParser::from_toml(toml)?;
        self.parsers.retain(|x| x.name() != p.name());
        self.parsers.insert(0, Box::new(p));
        Ok(())
    }

    pub fn parsers(&self) -> impl Iterator<Item = &dyn Parser> {
        self.parsers.iter().map(|p| p.as_ref())
    }

    pub fn get(&self, name: &str) -> Option<&dyn Parser> {
        self.parsers().find(|p| p.name() == name)
    }

    pub fn detect(&self, text: &str) -> &dyn Parser {
        let mut end = text.len().min(64 * 1024);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let sample = &text[..end];
        let mut best: (&dyn Parser, f32) = (&Raw, 0.0);
        for p in self.parsers() {
            let score = p.detect(sample);
            if score > best.1 {
                best = (p, score);
            }
        }
        best.0
    }
}

/// Fallback: one event per non-empty line, `key=value` pairs as fields.
pub struct Raw;

impl Parser for Raw {
    fn name(&self) -> &str {
        "raw"
    }
    fn description(&self) -> &str {
        "Plain text, one event per line; key=value pairs become fields"
    }
    fn detect(&self, _: &str) -> f32 {
        0.01
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        line_events(text, "raw", |l| Ok((kv_pairs(l), None)))
    }
    fn group_key(&self, _: &Event) -> Option<String> {
        None
    }
}

type LineResult = Result<(IndexMap<String, String>, Option<String>), String>;

/// One event per non-empty line. `f` returns the fields and timestamp, or an error
/// that is recorded on the event.
pub(crate) fn line_events(
    text: &str,
    format: &str,
    mut f: impl FnMut(&str) -> LineResult,
) -> Vec<Event> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let s = start;
        start += line.len();
        let body = line.trim_end_matches('\n');
        if body.trim().is_empty() {
            continue;
        }
        let (fields, timestamp, error) = match f(body) {
            Ok((fields, ts)) => (fields, ts, None),
            Err(e) => (IndexMap::new(), None, Some(e)),
        };
        let n = i as u32 + 1;
        out.push(Event {
            index: out.len(),
            span: Span::new(s, s + body.len()),
            lines: (n, n),
            timestamp,
            fields,
            format: format.to_string(),
            error,
        });
    }
    out
}

/// Fraction of the first 20 non-empty lines that match.
pub(crate) fn line_ratio(sample: &str, re: &Regex) -> f32 {
    let lines: Vec<&str> = sample
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(20)
        .collect();
    if lines.is_empty() {
        return 0.0;
    }
    lines.iter().filter(|l| re.is_match(l)).count() as f32 / lines.len() as f32
}

static KV: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s,;])([A-Za-z_][\w.-]{0,63})=("(?:[^"\\]|\\.)*"|'[^']*'|[^\s"',;]+)"#)
        .expect("KV regex")
});

pub(crate) fn kv_pairs(s: &str) -> IndexMap<String, String> {
    let mut out = IndexMap::new();
    for c in KV.captures_iter(s) {
        let v = &c[2];
        let v = if v.len() >= 2
            && (v.starts_with('"') && v.ends_with('"') || v.starts_with('\'') && v.ends_with('\''))
        {
            &v[1..v.len() - 1]
        } else {
            v
        };
        out.entry(c[1].to_string()).or_insert_with(|| v.to_string());
    }
    out
}

/// Entity type for a field name, from the last non-numeric path segment.
pub fn guess_field_type(field: &str) -> Option<EntityType> {
    use EntityType::*;
    let last = field
        .rsplit('.')
        .find(|s| !s.is_empty() && !s.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(field);
    let key = last.to_ascii_lowercase().replace(['-', ' '], "_");
    Some(match key.as_str() {
        "src" | "dst" | "src_ip" | "srcip" | "source_ip" | "sourceip" | "sourceipaddress"
        | "dest_ip" | "dst_ip" | "destip" | "destination_ip" | "destinationip" | "client_ip"
        | "clientip" | "client_public_ip" | "ip" | "ipaddress" | "ip_address" | "remote_ip"
        | "remoteip" | "remote_addr" | "remoteaddr" | "host_ip" | "hostip" | "srcipaddr"
        | "destipaddr" | "hostipaddr" | "callerip" | "c_ip" | "s_ip" | "client" | "server_ip"
        | "nat_ip" | "xff" | "x_forwarded_for" => Ip,
        "host" | "hostname" | "host_name" | "computer" | "computername" | "computer_name"
        | "workstation" | "workstationname" | "workstation_name" | "shost" | "dhost"
        | "dvchost" | "src_host" | "dst_host" | "dest_host" | "src_host_name" | "dst_host_name"
        | "dest_host_name" | "source_host" | "srcname" | "destname" | "device_name"
        | "devicename" | "machine" | "machinename" | "machine_name" | "identhostname"
        | "targetdomainname" | "subjectdomainname" | "domain" | "targetservername"
        | "servername" | "server_name" | "clientname" | "client_name" => Hostname,
        "user"
        | "username"
        | "user_name"
        | "usrname"
        | "suser"
        | "duser"
        | "account"
        | "accountname"
        | "account_name"
        | "targetusername"
        | "subjectusername"
        | "logonuser"
        | "src_user"
        | "dst_user"
        | "dest_user"
        | "login"
        | "userprincipalname"
        | "upn"
        | "samaccountname"
        | "actor"
        | "principal"
        | "owner"
        | "membername"
        | "targetoutboundusername" => Username,
        "email" | "mail" | "sender" | "recipient" | "from_address" | "to_address"
        | "user_email" | "emailaddress" => Email,
        "url" | "uri" | "request" | "referer" | "referrer" | "request_url" | "url_full"
        | "full_url" => Url,
        "process"
        | "process_name"
        | "processname"
        | "newprocessname"
        | "image"
        | "parentimage"
        | "exe"
        | "sproc"
        | "dproc"
        | "parentprocessname"
        | "parent_process_name"
        | "process_path" => Process,
        "file" | "filename" | "file_name" | "filepath" | "file_path" | "fname" | "path"
        | "targetfilename" | "target_filename" => FilePath,
        "mac" | "smac" | "dmac" | "srcmac" | "dstmac" | "mac_address" | "macaddress" | "dvcmac" => {
            Mac
        }
        "md5" | "sha1" | "sha256" | "hash" | "filehash" | "file_hash" => Sha256,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_registry_loads_and_detects_raw_fallback() {
        let r = Registry::builtin();
        assert!(r.get("winlogbeat").is_some());
        assert_eq!(r.detect("just some words").name(), "raw");
    }

    #[test]
    fn kv() {
        let kv = kv_pairs(r#"a=1 user="j doe" host=ws-1,x='y'"#);
        assert_eq!(kv["user"], "j doe");
        assert_eq!(kv["host"], "ws-1");
        assert_eq!(kv["x"], "y");
    }
}
