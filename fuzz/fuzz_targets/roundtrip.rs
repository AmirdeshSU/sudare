#![no_main]
//! Masking arbitrary input in strict mode: no panic, and no masked value survives as a
//! whole word in the output.

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use sudare_core::{Engine, Policy};

static ENGINE: LazyLock<Engine> = LazyLock::new(|| Engine::new(Policy::default().strict()).unwrap());

fn whole_word(text: &str, w: &str) -> bool {
    let glued = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-');
    text.match_indices(w)
        .any(|(i, _)| !glued(text[..i].chars().next_back()) && !glued(text[i + w.len()..].chars().next()))
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let p = ENGINE.prepare(&text, None, [7; 32]).unwrap();
    let masked = p.input.text();
    for (token, _, _) in p.map.tokens() {
        let original = p.map.original(token).unwrap();
        if original.chars().count() >= 3 && !original.starts_with("[[") {
            assert!(!whole_word(masked, original), "{original:?} survived in {masked:?}");
        }
    }
    let _ = p.map.unmask(masked);
});
