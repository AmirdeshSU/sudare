# Handover

State as of 2026-11-15, `main` at the commit that added this file. Verified items were run on a fresh clone; the rest are marked.

## Current state

Complete and working: core masking library, CLI, Python bindings, HTTP server + React UI, FortiSIEM pull connector, the standalone browser app (masks in wasm, calls the LLM provider directly with the visitor's key), and on-prem packaging (`deploy/`). 63 Rust tests and 7 web tests pass; clippy, fmt and a 5-minute fuzz run are clean; CI is green. A real-browser run against Gemini showed no leaks. Version `0.1.0`, **not yet released** (no tag).

## Where things live (accounts you must be able to log in to)

| What | Where | Credential / how to get access |
|---|---|---|
| Source | github.com/AmirdeshSU/sudare (public) | GitHub account `AmirdeshSU`; `gh auth login` on the laptop |
| Actions, Pages, ghcr.io image | same repo | no secrets configured; workflows use the built-in `GITHUB_TOKEN` |
| Vercel project `sudare` | team `amir61` | Vercel account login. Needed only to change settings. |
| LLM provider keys (Gemini etc.) | never in the repo. The Gemini key used for testing is exported in this machine's shell environment (`GEMINI_API_KEY` or `GOOGLE_API_KEY`), not in a profile file I found | copy it by hand over a secure channel, or create a new one; never commit it |
| Server secret key | generated per install | `sudare keygen`; back up with the data |

Nothing else must be transferred: no database, no uploaded data, no `.env` files exist in the repo. The only secret outside the repo is that environment key.

Git identity for this repo (repo-local config, not global): user `AmirdeshSU`. Commit messages in this project end with a `Claude-Session:` line.

## Decisions worth knowing

- **Mask map never leaves the process.** In the browser it lives in wasm memory only; JS sees masked prompts. `sudare-core` has no network code; only `sudare-egress` does.
- **Review before send is enforced server-side** (`confirm_digest`, HTTP 428), not just in the UI.
- **`sudare_core::analysis`** holds the offline half of the pipeline (`begin` / `retry` / `finish`) so server and browser share it.
- **Placeholders and built-in accounts are not masked** (`nil`, `none`, `root`, `daemon`...): they name nobody.
- **Mask propagation uses an overlapping Aho-Corasick search**; leftmost-longest let repeated values escape.
- **Strict CSP** on the standalone app; keys go in headers, never URLs; Vercel Analytics off.
- Fixtures synthetic only. No copyleft dependencies; nothing that phones home.

## Known issues and gaps

- `ghcr.io/amirdeshsu/sudare` visibility not confirmed (my token lacked `read:packages`). If `docker compose pull` says "denied", make the package public in GitHub package settings.
- The release `assets` job (binary + static bundle + checksums) has never run; first `v*.*.*` tag will be its first test.
- Docker image build and `docker compose up` were not re-run for this handover (CI builds the image; compose profiles were not exercised end to end here).
- The standalone Vercel page was checked by headers only, not in a browser (the same build passed the Gemini browser test on Pages).
- Self-signed FortiSIEM certificates are not supported (no CA-file setting).
- No monitoring, no secret-key rotation tooling.

## Next work (roadmap, none started)

CA-file setting for FortiSIEM; per-user FortiSIEM credentials; Elastic/Wazuh/Splunk connectors; response compression; SBOM and image signing; `.evtx` upload in the UI; custom domain for the Vercel site.

## Migration checklist

1. Install Rust, the wasm target, wasm-bindgen-cli 0.2.130, Node 24 ([DEVELOPMENT.md](DEVELOPMENT.md)).
2. `gh auth login`, `git clone`, set repo-local `user.name`/`user.email`.
3. `cargo test --workspace` and the web steps from DEVELOPMENT.md; all should pass.
4. Log in to Vercel (dashboard) if you will touch the deploy; confirm `main` pushes still deploy.
5. Re-create provider API keys in your own shell or in the app (they are never in the repo).
6. Check the ghcr.io package visibility; decide on tagging `v0.1.0`.
7. Delete build caches on the old machine only after step 3 passes (`target/` is ~16 GB, `fuzz/target` ~1 GB; both are gitignored and rebuildable; `fuzz/corpus` is gitignored too, so copy it if you want to keep the fuzzing progress).
