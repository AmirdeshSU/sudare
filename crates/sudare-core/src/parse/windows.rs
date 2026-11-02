//! Windows Event Log as XML (wevtutil / Get-WinEvent ToXml / .evtx conversion).
//!
//! The event schema is fixed and machine-written, so a handful of regexes read it;
//! a full XML parser would add a dependency for no extra coverage.

use super::Parser;
use crate::normalize::LineIndex;
use crate::types::{Event, Span};
use indexmap::IndexMap;
use regex::Regex;
use std::sync::LazyLock;

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> =
            LazyLock::new(|| Regex::new($pat).expect(stringify!($name)));
    };
}

re!(EVENT_OPEN, r"<Event[\s>]");
re!(EVENT_ID, r"<EventID(?:\s[^>]*)?>\s*(\d+)\s*</EventID>");
re!(TIME, r#"<TimeCreated\s+SystemTime=["']([^"']+)["']"#);
re!(COMPUTER, r"<Computer>([^<]*)</Computer>");
re!(CHANNEL, r"<Channel>([^<]*)</Channel>");
re!(PROVIDER, r#"<Provider\s+Name=["']([^"']+)["']"#);
re!(USER_ID, r#"<Security\s+UserID=["']([^"']+)["']"#);
re!(DATA, r#"<Data\s+Name=["']([^"']+)["']\s*>([^<]*)</Data>"#);

pub fn is_evtx(bytes: &[u8]) -> bool {
    bytes.starts_with(b"ElfFile\0")
}

/// Convert a binary .evtx file to one XML event per record.
#[cfg(feature = "evtx")]
pub fn evtx_to_xml(bytes: &[u8]) -> Result<String, String> {
    let mut parser = evtx::EvtxParser::from_buffer(bytes.to_vec()).map_err(|e| e.to_string())?;
    let mut out = String::new();
    let mut unreadable = 0usize;
    for record in parser.records() {
        match record {
            Ok(r) => {
                out.push_str(r.data.trim());
                out.push('\n');
            }
            Err(_) => unreadable += 1,
        }
    }
    if out.is_empty() && unreadable > 0 {
        return Err(format!("{unreadable} unreadable records and none readable"));
    }
    Ok(out)
}

fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|&e| e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let ch = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => ent
                .strip_prefix("#x")
                .map(|h| u32::from_str_radix(h, 16))
                .or_else(|| ent.strip_prefix('#').map(str::parse))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

pub struct WinXml;

impl Parser for WinXml {
    fn name(&self) -> &str {
        "winxml"
    }
    fn description(&self) -> &str {
        "Windows Event Log XML (wevtutil, Get-WinEvent ToXml(), converted .evtx)"
    }
    fn detect(&self, sample: &str) -> f32 {
        let event = EVENT_OPEN.is_match(sample);
        let schema = sample.contains("<EventID")
            || sample.contains("schemas.microsoft.com/win/2004/08/events/event");
        if event && schema { 0.92 } else { 0.0 }
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        let li = LineIndex::new(text);
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some(m) = EVENT_OPEN.find_at(text, pos) {
            let start = m.start();
            let (end, closed) = match text[start..].find("</Event>") {
                Some(e) => (start + e + "</Event>".len(), true),
                None => (text.len(), false),
            };
            let rec = &text[start..end];
            let mut f = IndexMap::new();
            let mut put = |k: &str, re: &Regex| {
                if let Some(c) = re.captures(rec) {
                    f.insert(k.to_string(), xml_unescape(c[1].trim()));
                }
            };
            put("EventID", &EVENT_ID);
            put("TimeCreated", &TIME);
            put("Computer", &COMPUTER);
            put("Channel", &CHANNEL);
            put("Provider", &PROVIDER);
            put("UserID", &USER_ID);
            for c in DATA.captures_iter(rec) {
                f.insert(format!("EventData.{}", &c[1]), xml_unescape(&c[2]));
            }
            let error = if !closed {
                Some("unterminated <Event>".to_string())
            } else if !f.contains_key("EventID") {
                Some("no <EventID>".to_string())
            } else {
                None
            };
            out.push(Event {
                index: out.len(),
                span: Span::new(start, end),
                lines: (li.line(start), li.line(end.saturating_sub(1).max(start))),
                timestamp: f.get("TimeCreated").cloned(),
                fields: f,
                format: "winxml".into(),
                error,
            });
            pos = end.max(start + 1);
        }
        out
    }
    fn self_fields(&self) -> Vec<String> {
        vec!["Computer".into()]
    }
    fn group_key(&self, e: &Event) -> Option<String> {
        e.fields.get("EventID").cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_system_and_event_data() {
        let x = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-10-29T15:01:02Z'/><Computer>dc01.corp.example.com</Computer></System><EventData><Data Name='TargetUserName'>r&amp;kumar</Data></EventData></Event>\n<Event><System><Computer>x</Computer>";
        let ev = WinXml.parse(x);
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].fields["EventID"], "4625");
        assert_eq!(ev[0].fields["EventData.TargetUserName"], "r&kumar");
        assert_eq!(ev[1].error.as_deref(), Some("unterminated <Event>"));
    }

    #[test]
    fn unescape_entities() {
        assert_eq!(xml_unescape("a&lt;b&#x41;&#66;&bogus;&"), "a<bAB&bogus;&");
    }
}
