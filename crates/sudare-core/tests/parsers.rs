//! Every fixture: detected as the expected format, parsed without panicking, and the
//! parse plus masked output pinned by snapshots (fixed salt, so tokens are stable).

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use sudare_core::normalize::normalize;
use sudare_core::{Engine, Policy};

#[derive(Deserialize)]
struct Manifest {
    files: BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
struct Entry {
    parser: String,
    sensitive: Vec<String>,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn manifest() -> Manifest {
    serde_json::from_str(&std::fs::read_to_string(root().join("manifest.json")).unwrap()).unwrap()
}

fn read(name: &str) -> String {
    String::from_utf8_lossy(&std::fs::read(root().join(name)).unwrap()).into_owned()
}

fn engine() -> Engine {
    Engine::new(Policy::load(&root().join("policy.toml")).unwrap())
        .unwrap()
        .documentation_ranges_public()
}

#[test]
fn detects_each_format() {
    let e = engine();
    for (name, entry) in manifest().files {
        if name.starts_with("malformed/") {
            continue;
        }
        let detected = e
            .registry()
            .detect(&normalize(&read(&name)))
            .name()
            .to_string();
        assert_eq!(detected, entry.parser, "{name}");
    }
}

#[test]
fn malformed_input_is_reported_not_fatal() {
    let e = engine();
    for (name, entry) in manifest()
        .files
        .into_iter()
        .filter(|(n, _)| n.starts_with("malformed/"))
    {
        let p = e
            .prepare(&read(&name), Some(&entry.parser), [0; 32])
            .unwrap();
        assert!(p.parse_errors > 0, "{name}: expected parse errors");
        for s in &entry.sensitive {
            assert!(
                !p.input.text().contains(s.as_str()),
                "{name}: {s} survived masking"
            );
        }
    }
}

#[test]
fn snapshots() {
    let e = engine();
    for (name, entry) in manifest().files {
        let text = normalize(&read(&name));
        let parser = e.registry().get(&entry.parser).unwrap();
        let events: Vec<serde_json::Value> = parser
            .parse(&text)
            .iter()
            .map(|ev| {
                serde_json::json!({
                    "lines": ev.lines,
                    "timestamp": ev.timestamp,
                    "group": parser.group_key(ev),
                    "error": ev.error,
                    "fields": ev.fields,
                })
            })
            .collect();
        let p = e.prepare(&text, Some(&entry.parser), [0; 32]).unwrap();
        let snap = name.replace(['/', '.', '-'], "_");
        insta::assert_yaml_snapshot!(format!("{snap}_events"), events);
        insta::assert_snapshot!(format!("{snap}_masked"), p.input.text());
    }
}
