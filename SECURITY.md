# Security policy

Sudare's job is keeping sensitive values away from third parties, so a masking miss
counts as a security bug.

## Reporting

Please report privately through **GitHub Security Advisories** ("Report a
vulnerability" on the repository's Security tab). Don't open a public issue. If you
include logs, use synthetic data or redact them yourself first.

You'll get an acknowledgement within 3 working days and a fix or mitigation plan
within 30 days for confirmed issues. Credit is given unless you ask otherwise.

## In scope

- A sensitive value (internal IP, hostname, username, email, secret, internal URL)
  reaching an LLM or threat-intel provider in a mode where it should be masked.
- A non-public value sent to a threat-intel provider.
- The mask map, or unmasked report data, written to disk in clear or logged.
- Prompt injection that makes Sudare itself (not just the model's text) behave
  differently, e.g. skip masking or change where data is sent.
- Script or HTML execution from model output in any Sudare renderer.
- Input that makes a parser or extractor panic, hang or use unbounded memory.
- Dependencies with known vulnerabilities (we run `cargo deny check advisories` in CI).

## Out of scope

- What a model writes in its analysis (accuracy, hallucinations), beyond the
  validation Sudare promises (schema, ATT&CK IDs, line references).
- Values with no recognizable shape in free text (see "Does not protect against" in
  the README). Better extractors for them are welcome as normal issues.
- Issues requiring an already-compromised host.

## Supported versions

Pre-1.0: only the latest release gets fixes.

## Hardening checklist for contributors

- `sudare-core` must not depend on any networking crate (CI enforces this).
- Code that sends data accepts `MaskedPrompt` / `PublicIndicator`, never `&str`.
- Never log, `Debug`-print or serialize API keys or the mask map.
- Regexes come from the `regex` crate (linear time). No backtracking engines.
- New dependencies must pass `cargo deny check` (no GPL/AGPL; ask first for anything
  copyleft) and must not phone home.
