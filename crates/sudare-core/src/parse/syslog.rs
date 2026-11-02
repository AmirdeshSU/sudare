//! Syslog: RFC 3164 (BSD) and RFC 5424. Message `key=value` pairs become fields.

use super::{Parser, kv_pairs, line_events, line_ratio};
use crate::types::Event;
use regex::Regex;
use std::sync::LazyLock;

static RFC3164: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:<(\d{1,3})>)?([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (\S+) ([^\s:\[]+)(?:\[(\d+)\])?:? ?(.*)$")
        .expect("RFC3164 regex")
});
static RFC5424: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\"]|\\.|"(?:[^"\\]|\\.)*")*\])+)(?: (.*))?$"#)
        .expect("RFC5424 regex")
});
static SD_ELEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\[([^\s\]=]+)((?:\s+[^\s=\]]+="(?:[^"\\]|\\.)*")*)\s*\]"#)
        .expect("SD element regex")
});
static SD_PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"([^\s=\]]+)="((?:[^"\\]|\\.)*)""#).expect("SD param regex"));

pub struct Syslog3164;

impl Parser for Syslog3164 {
    fn name(&self) -> &str {
        "syslog3164"
    }
    fn description(&self) -> &str {
        "BSD syslog (RFC 3164): <PRI>Mmm dd hh:mm:ss host tag[pid]: message"
    }
    fn detect(&self, sample: &str) -> f32 {
        line_ratio(sample, &RFC3164) * 0.7
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        line_events(text, "syslog3164", |line| {
            let c = RFC3164.captures(line).ok_or("not an RFC 3164 line")?;
            let mut f = indexmap::IndexMap::new();
            if let Some(p) = c.get(1) {
                f.insert("pri".to_string(), p.as_str().to_string());
            }
            f.insert("timestamp".into(), c[2].to_string());
            f.insert("hostname".into(), c[3].to_string());
            f.insert("app".into(), c[4].to_string());
            if let Some(pid) = c.get(5) {
                f.insert("pid".into(), pid.as_str().to_string());
            }
            let msg = c.get(6).map_or("", |m| m.as_str());
            for (k, v) in kv_pairs(msg) {
                f.entry(k).or_insert(v);
            }
            f.insert("message".into(), msg.to_string());
            Ok((f, Some(c[2].to_string())))
        })
    }
    fn self_fields(&self) -> Vec<String> {
        vec!["hostname".into()]
    }
    fn group_key(&self, e: &Event) -> Option<String> {
        e.fields.get("app").cloned()
    }
}

pub struct Syslog5424;

impl Parser for Syslog5424 {
    fn name(&self) -> &str {
        "syslog5424"
    }
    fn description(&self) -> &str {
        "Syslog (RFC 5424) with structured data"
    }
    fn detect(&self, sample: &str) -> f32 {
        line_ratio(sample, &RFC5424) * 0.85
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        line_events(text, "syslog5424", |line| {
            let c = RFC5424.captures(line).ok_or("not an RFC 5424 line")?;
            let mut f = indexmap::IndexMap::new();
            let names = ["pri", "timestamp", "hostname", "app", "procid", "msgid"];
            for (i, name) in names.iter().enumerate() {
                let v = &c[i + 1];
                if v != "-" {
                    f.insert(name.to_string(), v.to_string());
                }
            }
            for el in SD_ELEMENT.captures_iter(&c[7]) {
                for p in SD_PARAM.captures_iter(&el[2]) {
                    f.insert(
                        format!("sd.{}.{}", &el[1], &p[1]),
                        p[2].replace("\\\"", "\"").replace("\\]", "]"),
                    );
                }
            }
            let msg = c.get(8).map_or("", |m| m.as_str());
            for (k, v) in kv_pairs(msg) {
                f.entry(k).or_insert(v);
            }
            f.insert("message".into(), msg.to_string());
            let ts = f.get("timestamp").cloned();
            Ok((f, ts))
        })
    }
    fn self_fields(&self) -> Vec<String> {
        vec!["hostname".into()]
    }
    fn group_key(&self, e: &Event) -> Option<String> {
        e.fields
            .get("msgid")
            .or_else(|| e.fields.get("app"))
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3164() {
        let ev = Syslog3164
            .parse("<34>Oct 29 14:11:40 fw01 sshd[22]: Failed for jdoe user=jdoe\nnot syslog\n");
        assert_eq!(ev[0].fields["hostname"], "fw01");
        assert_eq!(ev[0].fields["app"], "sshd");
        assert_eq!(ev[0].fields["user"], "jdoe");
        assert!(ev[1].error.is_some());
    }

    #[test]
    fn rfc5424_structured_data() {
        let ev = Syslog5424.parse(r#"<165>1 2026-10-29T14:20:01Z app-02 web 42 AUTH [meta@1 user="asmith" src="192.0.2.4"] login failed"#);
        assert_eq!(ev[0].fields["hostname"], "app-02");
        assert_eq!(ev[0].fields["sd.meta@1.user"], "asmith");
        assert_eq!(ev[0].fields["message"], "login failed");
    }
}
