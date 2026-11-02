# Changelog

## Unreleased: phase 2 (core, CLI, Python)

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
- Server, web UI and encrypted history (phase 3); browser masking playground (phase 4).
- SIEM connectors (pull alerts / push notes): planned after the server.
