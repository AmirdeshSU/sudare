#![no_main]
//! Masking arbitrary input in strict mode: no panic, and no masked value survives as a
//! whole word in the output.

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use sudare_core::{Engine, Policy};

static ENGINE: LazyLock<Engine> = LazyLock::new(|| Engine::new(Policy::default().strict()).unwrap());

/// `w` occurs as a whole word outside every token in `tokens` (byte ranges).
fn survives(text: &str, w: &str, tokens: &[(usize, usize)]) -> bool {
    let glued = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-');
    text.match_indices(w).any(|(i, _)| {
        let e = i + w.len();
        !tokens.iter().any(|&(s, t)| i < t && s < e)
            && !glued(text[..i].chars().next_back())
            && !glued(text[e..].chars().next())
    })
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let p = ENGINE.prepare(&text, None, [7; 32]).unwrap();
    let masked = p.input.text();
    // Tokens themselves don't count: a value like "[USER_84]" can be the inside of the
    // token [[USER_84]] that replaced it.
    let tokens: Vec<(usize, usize)> = p
        .map
        .tokens()
        .flat_map(|(t, _, _)| masked.match_indices(t).map(|(i, m)| (i, i + m.len())))
        .collect();
    for (token, _, _) in p.map.tokens() {
        let original = p.map.original(token).unwrap();
        if original.chars().count() >= 3 && !original.starts_with("[[") {
            assert!(!survives(masked, original, &tokens), "{original:?} survived in {masked:?}");
        }
    }
    let _ = p.map.unmask(masked);
});
