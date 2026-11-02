# Contributing

Thanks for helping. Two rules matter more than any other:

1. **No real logs, ever**: not in fixtures, issues, PRs or commit history. Use
   documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
   2001:db8::/32), `example.com` / `example.org` and invented names. `gitleaks` runs in
   pre-commit and CI.
2. **No copyleft and nothing that phones home.** `cargo deny check` enforces the
   licence allowlist. Open an issue before adding a dependency whose licence isn't
   already allowed.

## Setup

```sh
rustup toolchain install stable
pre-commit install            # gitleaks + fmt + clippy on commit
cargo test --workspace
```

| Crate | Role |
|---|---|
| `sudare-core` | parse, extract, classify, mask, prompt, validate, unmask. No network, `#![forbid(unsafe_code)]`. |
| `sudare-egress` | the only crate that talks to the network: `Http`, LLM providers, threat intel, cache, pipeline. |
| `sudare-cli` | the `sudare` binary. |
| `sudare-py` | Python bindings (PyO3). |

Snapshots use [insta](https://insta.rs): review changes with `cargo insta review`.

## Add a parser

### JSON-shaped formats: a TOML mapping, no Rust

Copy `crates/sudare-core/mappings/winlogbeat.toml`:

```toml
name = "myvendor"
description = "MyVendor alerts exported as JSON"
base = "json"                      # or "ndjson"
detect.all_keys = ["alert.id", "alert.src_host"]   # all must be present
timestamp = { field = "alert.time" }
group_key = "alert.rule"           # event type, used for sampling rare types first
self_fields = ["sensor.hostname"]  # where the source names itself (internal domain learning)

[fields]                           # flattened path → ip | hostname | fqdn | url | email |
"alert.src_host" = "hostname"      #   username | hash | file_path | mac | process | cve | secret
"alert.user" = "username"
```

Fields you don't list are typed from their name (`user`, `src_ip`, `hostname`, ...).
Load a mapping without rebuilding: `sudare --mappings DIR analyze ...`. To ship one,
add it to `mappings/`, register it in `parse/json.rs` (`BUILTIN_MAPPINGS`), and add a
synthetic fixture plus its expected values to `fixtures/manifest.json`.

Only map layouts that are **publicly documented**. If the vendor doesn't document the
export, add a stub page under `docs/parsers/` (see `seceon.md`) instead of guessing.

### Other formats: implement `Parser`

```rust
pub trait Parser: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn detect(&self, sample: &str) -> f32;          // 0.0..=1.0 on the first 64 KiB
    fn parse(&self, text: &str) -> Vec<Event>;      // never panics
    fn field_type(&self, field: &str) -> Option<EntityType>;
    fn self_fields(&self) -> Vec<String>;
    fn group_key(&self, event: &Event) -> Option<String>;
}
```

`parse` must not panic on any input. A record it can't read becomes an `Event` with
`error` set, and its text is still masked. Use only the `regex` crate. Add a fixture,
a manifest entry and a `line_ratio`-style `detect`. The property tests and fuzz
targets pick the new parser up automatically.

## Add a provider

### LLM

Most hosted models speak the OpenAI API: try `--provider openai-compatible` first.
For a new wire format, add a `ProviderKind` in `crates/sudare-egress/src/llm.rs`, then:

- a request shape in `Provider::request`, built only from the `MaskedPrompt`;
- response parsing in `Provider::text`;
- the key in a header, never in the URL;
- a case in `tests/leak.rs` (the leak test is release-blocking).

### Threat intel

Implement `Enricher` in `crates/sudare-egress/src/ti.rs`:

- `lookup` takes a `PublicIndicator` and never errors: failures are a `TiStatus`.
- Lookups only; never submit samples or URLs.
- Pick a `RateLimit` that fits the provider's free tier.
- Document its terms in the README table.
- Add it to `TiRunner::from_env` and to the leak test's `runner()`.

## Tests that must stay green

- `tests/leak.rs`: every fixture × every LLM adapter × default and strict mode. No
  `sensitive` manifest value may appear in any request, raw or decoded.
- Property tests (`proptest`): masking hides generated values and unmasking restores
  the input exactly; no input or parser panics.
- `cargo fuzz`: `parse` and `roundtrip` targets (nightly), smoke-run in CI.
