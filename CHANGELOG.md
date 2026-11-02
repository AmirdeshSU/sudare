# Changelog

## Unreleased: phase 3 (server)

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
- Web UI and browser masking playground (phase 4).
- SIEM connectors (pull alerts / push notes): planned after the server.
