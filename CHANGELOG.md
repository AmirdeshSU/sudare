# Changelog

## Unreleased: SIEM connectors

### Added
- FortiSIEM connector, pull only: `sudare pull fortisiem <incident>` and
  `POST /api/pull/fortisiem`, with a "FortiSIEM incident" box in the UI. OAuth client
  credentials or a token; `https://` required; incident ids must be numeric. Pulled
  events go through the normal preview, masking and confirmation.
- `/api/me` lists configured connectors.

## Earlier: phase 4 (web UI)

### Added
- Web UI (React, Vite, TypeScript), embedded in the binary with `rust-embed`:
  - paste or upload, then a line-by-line diff of original and masked text before any send
  - an explicit confirmation naming the provider and URL for cloud providers, for analyses and chat
  - report, follow-up chat, history, API keys, retention and user management
  - model output rendered as text nodes only, links defanged; lint forbids `dangerouslySetInnerHTML`
- `sudare-wasm` and the `#/playground` page: masking in the browser, no login, nothing sent.
- `/api/health` reports the login mode.
- CI: a `web` job (wasm build, eslint, tsc, vite build, tests). The Docker image builds wasm, the UI and the binary.

### Changed
- Page CSP adds `'wasm-unsafe-eval'` for the playground. Inline script and `eval` stay blocked.

### Licences
- Vite 8 needs `lightningcss` (MPL-2.0) at build time. Accepted: it is a build tool only, and none of its code ships in the UI bundle or the binary.

### Fixed
- Usernames in sshd/PAM phrasing ("Failed password for jdoe", "Invalid user x", "session opened for user x") were missed when they appeared nowhere else in the input.
- Entity verification dropped real paths from CEF, LEEF and JSON input, which escape backslashes, when the model quoted them unescaped. Found in a live Gemini run.

## Earlier: phase 3 (server)

### Added
- `sudare-server` (axum) and `sudare serve` / `sudare keygen`:
  - single-user token login, or multi-user with argon2id passwords
  - HttpOnly SameSite=Strict sessions, CSRF tokens, Host allowlist, Origin check
  - login lockout, and security headers with a strict CSP
- Server-enforced review: a cloud provider needs the masked preview's digest (`428` otherwise), for analyses and chat alike.
- Per-user API keys sealed with XChaCha20-Poly1305 and never returned.
- History: masked input, unmasked report, and sealed mask map plus chat. Delete removes all three. Retention purge runs at startup, hourly and on settings change.
- `Prepared::seal` / `open` in core: the only way a mask map is ever serialized.
- `deploy/Dockerfile` (distroless, non-root, 63 MB) and `deploy/docker-compose.yml` (127.0.0.1 only, read-only, optional Ollama profile).

### Changed
- `evtx` 0.14 → 0.15.1 (RUSTSEC-2026-0431; the affected feature was never enabled here).

## Earlier: phase 2 (core, CLI, Python)

### Added
- `sudare-core`:
  - normalization (NFKC, invisible-character removal)
  - parsers for RFC 3164/5424 syslog, CEF, LEEF 1.0/2.0, Windows XML and native `.evtx`, JSON, NDJSON and raw text
  - TOML mappings for Winlogbeat, PowerShell `Get-WinEvent` and the FortiSIEM REST API
  - entity extraction with spans, and internal/public/reserved scope with domain learning
  - reversible typed masking with salted HMAC numbering, a policy file, rules and allow/deny lists
  - prompt building with nonce delimiters and line references, and stratified sampling over budget
  - schema validation, the ATT&CK v20.0 index (revoked → successor), unmasking and safe markdown
- `sudare-egress`:
  - Ollama, OpenAI, Anthropic, Gemini and OpenAI-compatible providers
  - VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox and GreyNoise lookups, with pacing, per-run caps and a SQLite cache
  - an analysis pipeline with one retry, plus chat
- `sudare` CLI: `parsers`, `mask` (`--diff`, `--show-map`) and `analyze` (`--mode`, `--policy`, `--yes`, `--chat`, `--format md|json`). Cloud providers need the masked-input preview confirmed.
- `sudare` Python module (`mask`, `MaskResult.unmask`, `parsers`).
- Tests:
  - snapshots per fixture
  - property tests for the round trip and for panics
  - hostile-input tests: injection, XSS, look-alike Unicode and ReDoS
  - a leak test across every fixture, LLM adapter and mode, with a negative control
  - fuzz targets

### Not yet
- SIEM connectors (pull alerts / push notes): planned after the server. FortiSIEM pull has since landed; Elastic, Splunk, Wazuh and push are still to come.
