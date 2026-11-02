//! ArcSight CEF and IBM QRadar LEEF (1.0 and 2.0), with or without a syslog prefix.

use super::{Parser, line_events, line_ratio};
use crate::types::Event;
use indexmap::IndexMap;
use regex::Regex;
use std::sync::LazyLock;

static CEF_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"CEF:\d+\|").expect("CEF regex"));
static LEEF_START: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"LEEF:(\d(?:\.\d)?)\|").expect("LEEF regex"));
/// Hostname from a BSD syslog header in front of the CEF/LEEF payload.
static SYSLOG_PREFIX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:<\d{1,3}>)?[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} (\S+)")
        .expect("syslog prefix regex")
});

fn prefix_host(prefix: &str, f: &mut IndexMap<String, String>) {
    if let Some(c) = SYSLOG_PREFIX.captures(prefix) {
        f.insert("syslog.hostname".into(), c[1].to_string());
    }
}

static EXT_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)([A-Za-z0-9_][A-Za-z0-9_.\[\]-]*)=").expect("extension key regex")
});

/// Split on unescaped `|` exactly `n` times; returns the unescaped parts and the rest.
fn split_header(s: &str, n: usize) -> Option<(Vec<String>, &str)> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut it = s.char_indices();
    while let Some((i, c)) = it.next() {
        match c {
            '\\' => {
                if let Some((_, next)) = it.next() {
                    cur.push(next);
                }
            }
            '|' => {
                parts.push(std::mem::take(&mut cur));
                if parts.len() == n {
                    return Some((parts, &s[i + 1..]));
                }
            }
            _ => cur.push(c),
        }
    }
    None
}

fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some(x @ ('=' | '\\' | '|')) => out.push(x),
            Some(x) => {
                out.push('\\');
                out.push(x);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// `key=value key2=value with spaces` — a value runs until the next ` key=`.
fn parse_extension(ext: &str, out: &mut IndexMap<String, String>) {
    let keys: Vec<(usize, usize, &str)> = EXT_KEY
        .captures_iter(ext)
        .filter_map(|c| {
            let (k, whole) = (c.get(1)?, c.get(0)?);
            Some((whole.start(), whole.end(), k.as_str()))
        })
        .collect();
    for (i, (_, value_start, key)) in keys.iter().enumerate() {
        let value_end = keys.get(i + 1).map_or(ext.len(), |n| n.0);
        let v = ext[*value_start..value_end].trim();
        out.entry(key.to_string()).or_insert_with(|| unescape(v));
    }
}

pub struct Cef;

impl Parser for Cef {
    fn name(&self) -> &str {
        "cef"
    }
    fn description(&self) -> &str {
        "ArcSight Common Event Format, optionally behind a syslog header"
    }
    fn detect(&self, sample: &str) -> f32 {
        line_ratio(sample, &CEF_START) * 0.95
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        line_events(text, "cef", |line| {
            let start = CEF_START.find(line).ok_or("no CEF header")?.start();
            let (h, ext) =
                split_header(&line[start + 4..], 7).ok_or("CEF header has fewer than 7 fields")?;
            let mut f = IndexMap::new();
            let names = [
                "cef_version",
                "device_vendor",
                "device_product",
                "device_version",
                "signature_id",
                "name",
                "severity",
            ];
            for (name, v) in names.iter().zip(h) {
                f.insert(name.to_string(), v);
            }
            prefix_host(&line[..start], &mut f);
            parse_extension(ext, &mut f);
            let ts = ["rt", "start", "end"]
                .iter()
                .find_map(|k| f.get(*k).cloned());
            Ok((f, ts))
        })
    }
    fn group_key(&self, e: &Event) -> Option<String> {
        e.fields.get("signature_id").cloned()
    }
}

pub struct Leef;

impl Parser for Leef {
    fn name(&self) -> &str {
        "leef"
    }
    fn description(&self) -> &str {
        "IBM QRadar Log Event Extended Format 1.0 / 2.0"
    }
    fn detect(&self, sample: &str) -> f32 {
        line_ratio(sample, &LEEF_START) * 0.95
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        line_events(text, "leef", |line| {
            let c = LEEF_START.captures(line).ok_or("no LEEF header")?;
            let v2 = c[1].starts_with('2');
            let start = c.get(0).map_or(0, |m| m.start()) + "LEEF:".len();
            let (h, attrs) = split_header(&line[start..], if v2 { 6 } else { 5 })
                .ok_or("LEEF header is incomplete")?;
            let mut f = IndexMap::new();
            let names = [
                "leef_version",
                "vendor",
                "product",
                "product_version",
                "event_id",
            ];
            for (name, v) in names.iter().zip(h.iter()) {
                f.insert(name.to_string(), v.clone());
            }
            prefix_host(&line[..start - "LEEF:".len()], &mut f);
            let delim = if v2 { leef2_delimiter(&h[5]) } else { '\t' };
            if attrs.contains(delim) {
                for pair in attrs.split(delim) {
                    if let Some((k, v)) = pair.split_once('=') {
                        f.entry(k.trim().to_string())
                            .or_insert_with(|| v.trim().to_string());
                    }
                }
            } else {
                parse_extension(attrs, &mut f);
            }
            let ts = f.get("devTime").cloned();
            Ok((f, ts))
        })
    }
    fn group_key(&self, e: &Event) -> Option<String> {
        e.fields.get("event_id").cloned()
    }
}

/// LEEF 2.0 names its delimiter as a character or hex (`^`, `x5E`, `0x5E`).
fn leef2_delimiter(s: &str) -> char {
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix('x'));
    match hex {
        Some(h) if !h.is_empty() => u32::from_str_radix(h, 16)
            .ok()
            .and_then(char::from_u32)
            .unwrap_or('\t'),
        _ => s.chars().next().unwrap_or('\t'),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cef_with_escapes_and_spaces() {
        let ev = Cef.parse(r"Oct 29 14:30:12 fw02 CEF:0|V|P\|X|1.0|100|Blocked thing|7|src=192.0.2.21 suser=CORP\\mlee msg=a b\=c act=blocked");
        let f = &ev[0].fields;
        assert_eq!(f["device_product"], "P|X");
        assert_eq!(f["suser"], r"CORP\mlee");
        assert_eq!(f["msg"], "a b=c");
        assert_eq!(f["act"], "blocked");
        assert_eq!(f["syslog.hostname"], "fw02");
    }

    #[test]
    fn leef_v1_and_v2() {
        let ev = Leef.parse("LEEF:1.0|V|P|1|SQLi|src=203.0.113.9\tusrName=dbadmin\nLEEF:2.0|V|P|1|Scan|^|src=198.51.100.2^identHostName=db02\n");
        assert_eq!(ev[0].fields["usrName"], "dbadmin");
        assert_eq!(ev[1].fields["identHostName"], "db02");
        assert_eq!(ev[1].fields["event_id"], "Scan");
    }

    #[test]
    fn short_header_is_error_not_panic() {
        assert!(Cef.parse("CEF:0|only|three")[0].error.is_some());
    }
}
