//! JSON document, NDJSON, and declarative TOML mappings built on either.

use super::{Parser, guess_field_type, line_events};
use crate::normalize::LineIndex;
use crate::types::{EntityType, Event, Span};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::Value;
use serde_json::value::RawValue;

pub(crate) const BUILTIN_MAPPINGS: &[&str] = &[
    include_str!("../../mappings/winlogbeat.toml"),
    include_str!("../../mappings/powershell-winevent.toml"),
    include_str!("../../mappings/fortisiem.toml"),
];

const TIMESTAMP_KEYS: &[&str] = &[
    "@timestamp",
    "timestamp",
    "time",
    "eventTime",
    "EventTime",
    "TimeCreated",
    "receiveTime",
    "date",
    "ts",
    "created_at",
];
const GROUP_KEYS: &[&str] = &[
    "event_type",
    "eventType",
    "event_id",
    "EventID",
    "eventName",
    "event.code",
    "event.action",
    "type",
    "action",
    "category",
    "rule.name",
    "signature",
    "alert.signature",
];

/// Flatten nested JSON into dotted paths: `{"a":{"b":[1]}}` → `a.b.0 = "1"`.
pub(crate) fn flatten(v: &Value, prefix: &str, out: &mut IndexMap<String, String>) {
    let key = |k: &str| {
        if prefix.is_empty() {
            k.to_string()
        } else {
            format!("{prefix}.{k}")
        }
    };
    match v {
        Value::Object(m) => m.iter().for_each(|(k, x)| flatten(x, &key(k), out)),
        Value::Array(a) => a
            .iter()
            .enumerate()
            .for_each(|(i, x)| flatten(x, &key(&i.to_string()), out)),
        Value::String(s) => {
            out.insert(key_or_value(prefix), s.clone());
        }
        Value::Number(n) => {
            out.insert(key_or_value(prefix), n.to_string());
        }
        Value::Bool(b) => {
            out.insert(key_or_value(prefix), b.to_string());
        }
        Value::Null => {}
    }
}

fn key_or_value(prefix: &str) -> String {
    if prefix.is_empty() {
        "value".into()
    } else {
        prefix.into()
    }
}

fn first_of(fields: &IndexMap<String, String>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| fields.get(*k).cloned())
}

/// Spans of the records in a JSON document: elements of a top-level array, of a
/// well-known wrapper array (`data`, `events`, `Records`, `hits.hits`, ...), or the
/// whole document.
fn record_spans(text: &str) -> Result<Vec<Span>, String> {
    let err = |e: serde_json::Error| e.to_string();
    let offset = |s: &str| s.as_ptr() as usize - text.as_ptr() as usize;
    let spans = |raws: Vec<&RawValue>| -> Vec<Span> {
        raws.iter()
            .map(|r| {
                let o = offset(r.get());
                Span::new(o, o + r.get().len())
            })
            .collect()
    };
    let root: &RawValue = serde_json::from_str(text).map_err(err)?;
    let body = root.get();
    if body.starts_with('[') {
        return Ok(spans(serde_json::from_str(body).map_err(err)?));
    }
    if body.starts_with('{') {
        let obj: IndexMap<String, &RawValue> = serde_json::from_str(body).map_err(err)?;
        for key in [
            "data", "events", "records", "Records", "results", "items", "value",
        ] {
            if let Some(raw) = obj.get(key)
                && raw.get().starts_with('[')
            {
                return Ok(spans(serde_json::from_str(raw.get()).map_err(err)?));
            }
        }
        if let Some(hits) = obj.get("hits")
            && let Ok(inner) = serde_json::from_str::<IndexMap<String, &RawValue>>(hits.get())
            && let Some(arr) = inner.get("hits")
        {
            return Ok(spans(serde_json::from_str(arr.get()).map_err(err)?));
        }
    }
    Ok(vec![Span::new(offset(body), offset(body) + body.len())])
}

fn record_event(text: &str, span: Span, index: usize, format: &str, li: &LineIndex) -> Event {
    let mut fields = IndexMap::new();
    let error = match serde_json::from_str::<Value>(&text[span.start..span.end]) {
        Ok(v) => {
            flatten(&v, "", &mut fields);
            None
        }
        Err(e) => Some(e.to_string()),
    };
    Event {
        index,
        span,
        lines: (
            li.line(span.start),
            li.line(span.end.saturating_sub(1).max(span.start)),
        ),
        timestamp: first_of(&fields, TIMESTAMP_KEYS),
        fields,
        format: format.into(),
        error,
    }
}

fn parse_document(text: &str, format: &str) -> Vec<Event> {
    let li = LineIndex::new(text);
    match record_spans(text) {
        Ok(spans) => spans
            .into_iter()
            .enumerate()
            .map(|(i, s)| record_event(text, s, i, format, &li))
            .collect(),
        Err(e) => vec![Event {
            index: 0,
            span: Span::new(0, text.len()),
            lines: (1, li.count().max(1)),
            timestamp: None,
            fields: IndexMap::new(),
            format: format.into(),
            error: Some(e),
        }],
    }
}

fn parse_lines(text: &str, format: &str) -> Vec<Event> {
    line_events(text, format, |line| {
        let v: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        if !v.is_object() {
            return Err("not a JSON object".into());
        }
        let mut fields = IndexMap::new();
        flatten(&v, "", &mut fields);
        let ts = first_of(&fields, TIMESTAMP_KEYS);
        Ok((fields, ts))
    })
}

fn object_lines(sample: &str) -> (usize, usize) {
    let lines: Vec<&str> = sample
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(5)
        .collect();
    let ok = lines
        .iter()
        .filter(|l| serde_json::from_str::<Value>(l).is_ok_and(|v| v.is_object()))
        .count();
    (ok, lines.len())
}

pub struct Json;

impl Parser for Json {
    fn name(&self) -> &str {
        "json"
    }
    fn description(&self) -> &str {
        "A JSON document: an array of events, a wrapper object (data, Records, hits.hits) or one object"
    }
    fn detect(&self, sample: &str) -> f32 {
        let t = sample.trim_start();
        if !(t.starts_with('[') || t.starts_with('{')) {
            return 0.0;
        }
        if serde_json::from_str::<&RawValue>(sample.trim()).is_ok() {
            return 0.62;
        }
        let (ok, n) = object_lines(sample);
        if n > 1 && ok == n { 0.3 } else { 0.5 }
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        parse_document(text, "json")
    }
    fn group_key(&self, e: &Event) -> Option<String> {
        first_of(&e.fields, GROUP_KEYS)
    }
}

pub struct Ndjson;

impl Parser for Ndjson {
    fn name(&self) -> &str {
        "ndjson"
    }
    fn description(&self) -> &str {
        "Newline-delimited JSON, one object per line"
    }
    fn detect(&self, sample: &str) -> f32 {
        match object_lines(sample) {
            (ok, n) if n > 1 && ok == n => 0.65,
            (1, 1) => 0.55,
            (ok, n) if n > 1 && ok * 2 > n => 0.4,
            _ => 0.0,
        }
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        parse_lines(text, "ndjson")
    }
    fn group_key(&self, e: &Event) -> Option<String> {
        first_of(&e.fields, GROUP_KEYS)
    }
}

/// A JSON-shaped format described in TOML instead of code. See `mappings/*.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mapping {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub base: Base,
    pub detect: Detect,
    pub timestamp: Option<FieldRef>,
    pub group_key: Option<String>,
    #[serde(default)]
    pub self_fields: Vec<String>,
    /// Flattened field path → entity type name (`ip`, `hostname`, `username`, ...).
    #[serde(default)]
    pub fields: IndexMap<String, String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Base {
    Json,
    Ndjson,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detect {
    /// Every key must appear in the sample.
    pub all_keys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldRef {
    pub field: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MappingError {
    #[error("mapping: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("mapping {name}: field {field:?} has unknown entity type {ty:?}")]
    Type {
        name: String,
        field: String,
        ty: String,
    },
    #[error("mapping {0}: detect.all_keys must not be empty")]
    NoKeys(String),
}

pub(crate) struct MappedParser {
    m: Mapping,
    types: IndexMap<String, EntityType>,
    needles: Vec<String>,
}

impl MappedParser {
    pub(crate) fn from_toml(s: &str) -> Result<Self, MappingError> {
        let m: Mapping = toml::from_str(s)?;
        if m.detect.all_keys.is_empty() {
            return Err(MappingError::NoKeys(m.name));
        }
        let mut types = IndexMap::new();
        for (field, ty) in &m.fields {
            let t = EntityType::from_name(ty).ok_or_else(|| MappingError::Type {
                name: m.name.clone(),
                field: field.clone(),
                ty: ty.clone(),
            })?;
            types.insert(field.clone(), t);
        }
        // Each path segment must appear as a quoted JSON key; robust to truncated samples.
        let needles = m
            .detect
            .all_keys
            .iter()
            .flat_map(|k| k.split('.'))
            .filter(|s| !s.chars().all(|c| c.is_ascii_digit()))
            .map(|s| format!("\"{s}\""))
            .collect();
        Ok(Self { m, types, needles })
    }
}

impl Parser for MappedParser {
    fn name(&self) -> &str {
        &self.m.name
    }
    fn description(&self) -> &str {
        &self.m.description
    }
    fn detect(&self, sample: &str) -> f32 {
        if self.needles.iter().all(|n| sample.contains(n.as_str())) {
            0.9
        } else {
            0.0
        }
    }
    fn parse(&self, text: &str) -> Vec<Event> {
        let mut events = match self.m.base {
            Base::Json => parse_document(text, &self.m.name),
            Base::Ndjson => parse_lines(text, &self.m.name),
        };
        if let Some(ts) = &self.m.timestamp {
            for e in &mut events {
                if let Some(v) = e.fields.get(&ts.field) {
                    e.timestamp = Some(v.clone());
                }
            }
        }
        events
    }
    fn field_type(&self, field: &str) -> Option<EntityType> {
        self.types
            .get(field)
            .cloned()
            .or_else(|| guess_field_type(field))
    }
    fn self_fields(&self) -> Vec<String> {
        self.m.self_fields.clone()
    }
    fn group_key(&self, e: &Event) -> Option<String> {
        match &self.m.group_key {
            Some(k) => e.fields.get(k).cloned(),
            None => first_of(&e.fields, GROUP_KEYS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_arrays_and_spans() {
        let text = "{\"data\":[{\"a\":1},\n{\"b\":\"x\"}],\"result\":{}}";
        let ev = Json.parse(text);
        assert_eq!(ev.len(), 2);
        assert_eq!(&text[ev[1].span.start..ev[1].span.end], "{\"b\":\"x\"}");
        assert_eq!(ev[1].lines, (2, 2));
    }

    #[test]
    fn malformed_document_is_one_error_event() {
        let ev = Json.parse("[{\"a\":1},");
        assert_eq!(ev.len(), 1);
        assert!(ev[0].error.is_some());
    }

    #[test]
    fn ndjson_bad_line_keeps_going() {
        let ev = Ndjson.parse("{\"a\":1}\nnot json\n{\"b\":2}\n");
        assert_eq!(ev.len(), 3);
        assert!(ev[1].error.is_some());
        assert_eq!(ev[2].fields["b"], "2");
    }
}
