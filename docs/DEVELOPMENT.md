# Development

Everything below was run on a fresh `git clone` (Linux, Rust 1.99.1, Node 24.18.0, wasm-bindgen 0.2.130) unless marked *unverified*.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Rust (rustup) | stable; MSRV 1.88 (`Cargo.toml`) | everything |
| `wasm32-unknown-unknown` target | | the browser build: `rustup target add wasm32-unknown-unknown` |
| `wasm-bindgen-cli` | exactly **0.2.130** | must match the `wasm-bindgen` crate: `cargo install wasm-bindgen-cli --version 0.2.130 --locked` |
| Node + npm | 24.x (CI and Docker use 24) | web UI |
| Docker + Compose | any recent | image build, on-prem (*optional*) |
| Python 3.10+, `maturin` | | Python bindings and their tests (*optional*) |
| `cargo-deny` | | licence/advisory check (*optional*, CI runs it) |
| nightly Rust + `cargo-fuzz` | | fuzzing (*optional*) |
| `pre-commit` | | gitleaks + fmt + clippy on commit (*optional*) |

Nothing is OS-specific. The only host paths are the defaults `~/.local/share/sudare` (server data) and `~/.cache/sudare` (threat-intel cache); override with `SUDARE_DATA_DIR` / `SUDARE_CACHE_DIR`.

## Setup

```sh
git clone https://github.com/AmirdeshSU/sudare.git && cd sudare
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked
cd web && npm ci && npm run wasm && cd ..
pre-commit install                      # optional
```

Environment: copy `.env.example` and export what you need. Every key is optional for development; Ollama needs none. `SUDARE_SECRET_KEY` is needed only for `sudare serve` (`cargo run -p sudare-cli -- keygen`).

## Commands

```sh
cargo test --workspace                  # unit, snapshot, property, leak tests (insta: `cargo insta review`)
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check

cd web
npm run wasm                            # rebuild the wasm after changing sudare-core or sudare-wasm
npm run lint && npm run build && npm test
npm run build:standalone                # the browser-only app -> web/dist-standalone
npm run watch                           # with `cargo run -p sudare-cli -- serve`

# Server with the UI (debug builds read web/dist from disk; release builds embed it, so build web/ first)
export SUDARE_SECRET_KEY=$(cargo run -q -p sudare-cli -- keygen)
cargo run -p sudare-cli -- serve

# Python bindings
cd crates/sudare-py && maturin build --release --out dist && pip install dist/*.whl pytest && pytest -q tests

# Fuzz (nightly)
cd fuzz && cargo +nightly fuzz run parse -- -max_total_time=60
cd fuzz && cargo +nightly fuzz run roundtrip -- -max_total_time=60
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests, `cargo deny`, gitleaks, the wasm/web/Python builds and a 60 s fuzz smoke; keep it green.

## Layout

See the crate table in [CONTRIBUTING.md](../CONTRIBUTING.md). Extra: `sudare-wasm` is the browser build of the masker plus the `Session` class the standalone app uses; `web/` holds both the server UI (`App`) and the standalone app (`views/Standalone.tsx`, chosen by `VITE_STANDALONE=1`).

## Rules that are enforced

- `sudare-core` has no network crate (CI job `core-has-no-network`) and forbids `unsafe`.
- No copyleft dependencies and nothing that phones home (`deny.toml`).
- Fixtures are synthetic only: documentation IP ranges, `example.com`, invented names. gitleaks runs over the whole history.
- The standalone CSP in `web/vite.config.ts` and `web/vercel.json` must match (a web test checks it). Adding a provider means editing both.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `npm run wasm` fails with a schema/version mismatch | `wasm-bindgen --version` is not 0.2.130 |
| Server shows "no web UI in this build" | release build without `web/dist`; run `npm run build` first |
| `sudare serve` refuses to start | `SUDARE_SECRET_KEY` missing or short, or a non-loopback `SUDARE_BIND` without `SUDARE_ALLOWED_HOSTS` |
| Browser call to Ollama blocked | start Ollama with `OLLAMA_ORIGINS=<page origin>` |
| `cargo +nightly fuzz` fails to build | needs nightly and `cargo install cargo-fuzz --locked` |
| `cargo deny` complains about `default-features` | keep `sudare-core` declared by path in `sudare-wasm/Cargo.toml` |
| Fuzz/roundtrip failure on a word like `nil` or `root` | those are deliberately not masked (`extract.rs` PLACEHOLDERS / WELL_KNOWN_ACCOUNTS) |
