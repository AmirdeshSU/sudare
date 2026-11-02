#![no_main]
//! Every parser, and detection, on arbitrary bytes: must never panic.

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use sudare_core::parse::Registry;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::builtin);

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = REGISTRY.detect(&text);
    for p in REGISTRY.parsers() {
        for e in p.parse(&text) {
            assert!(e.span.start <= e.span.end && e.span.end <= text.len());
            let _ = p.group_key(&e);
        }
    }
});
