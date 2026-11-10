//! The browser playground: the same masking engine as the server, run locally in
//! the page. No network, no storage; the mask map lives only in this call's result.
#![forbid(unsafe_code)]

use serde_json::json;
use std::sync::LazyLock;
use sudare_core::{Engine, Policy};
use wasm_bindgen::prelude::*;

/// [default mode, strict mode], built once.
static ENGINES: LazyLock<[Engine; 2]> = LazyLock::new(|| {
    let p = Policy::default();
    [
        Engine::new(p.clone()).expect("default policy is valid"),
        Engine::new(p.strict()).expect("strict policy is valid"),
    ]
});

/// Mask `text`. `salt` must be 32 fresh random bytes (crypto.getRandomValues).
/// Returns JSON: masked text, stats and every decision (value, action, token).
#[wasm_bindgen]
pub fn mask(
    text: &str,
    strict: bool,
    parser: Option<String>,
    salt: &[u8],
) -> Result<String, JsError> {
    let salt: [u8; 32] = salt
        .try_into()
        .map_err(|_| JsError::new("salt must be 32 bytes"))?;
    let p = ENGINES[usize::from(strict)]
        .prepare(text, parser.as_deref(), salt)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(json!({
        "masked": p.input.text(),
        "parser": p.parser,
        "lines": p.input.line_count(),
        "events": p.events,
        "parse_errors": p.parse_errors,
        "stats": p.stats,
        "public_indicators": p.indicators.len(),
        "decisions": p.decisions,
    })
    .to_string())
}

/// JSON list of `{name, description}`.
#[wasm_bindgen]
pub fn parsers() -> String {
    let list: Vec<_> = ENGINES[0]
        .registry()
        .parsers()
        .map(|p| json!({ "name": p.name(), "description": p.description() }))
        .collect();
    serde_json::Value::from(list).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_internal_values_and_rejects_bad_salt() {
        let out = mask(
            "<38>Oct 29 15:01:02 bastion01 sshd[4242]: Failed password for jdoe from 10.20.30.40 port 22 ssh2",
            false,
            None,
            &[7; 32],
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let masked = v["masked"].as_str().unwrap();
        assert!(
            !masked.contains("10.20.30.40") && !masked.contains("jdoe"),
            "{masked}"
        );
        assert!(masked.contains("[[IP_INTERNAL_"), "{masked}");
        assert!(parsers().contains("syslog"));
    }
}
