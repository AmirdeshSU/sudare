# Handover

State as of 2026-11-15, `main` at the commit that added this file; updated the same day after the `v0.1.0` release (see "Known issues and gaps" for what that resolved). Verified items were run on a fresh clone; the rest are marked.

## Current state

Complete and working: core masking library, CLI, Python bindings, HTTP server + React UI, FortiSIEM pull connector, the standalone browser app (masks in wasm, calls the LLM provider directly with the visitor's key), and on-prem packaging (`deploy/`). 63 Rust tests and 7 web tests pass; clippy, fmt and a 5-minute fuzz run are clean; CI is green. A real-browser run against Gemini showed no leaks.

**Released: `v0.1.0`** (tag on `538a26b`, GitHub release "Latest"). The release workflow's `image` and `assets` jobs both passed; the release carries `sudare-v0.1.0-linux-x86_64.tar.gz`, `sudare-standalone-v0.1.0.tar.gz` and `SHA256SUMS`. ghcr.io has `0.1.0`, `0.1`, `latest` and `edge`.

## Where things live (accounts you must be able to log in to)

| What | Where | Credential / how to get access |
|---|---|---|
| Source | github.com/AmirdeshSU/sudare (public) | GitHub account `AmirdeshSU`; `gh auth login` on the laptop |
| Actions, Pages, ghcr.io image | same repo | no secrets configured; workflows use the built-in `GITHUB_TOKEN` |
| Vercel project `sudare` | team `amir61` | Vercel account login. Needed only to change settings. |
| LLM provider keys (Gemini etc.) | never in the repo. The Gemini key used for testing is exported in this machine's shell environment (`GEMINI_API_KEY` or `GOOGLE_API_KEY`), not in a profile file I found | copy it by hand over a secure channel, or create a new one; never commit it |
| Server secret key | generated per install | `sudare keygen`; back up with the data |

Nothing else must be transferred: no database, no uploaded data, no `.env` files exist in the repo. The only secret outside the repo is that environment key. A local run with `SUDARE_DATA_DIR=.local-data` leaves a SQLite database in the checkout; it is gitignored, holds only test accounts, and can be deleted.

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

Resolved after this guide was first written (checked 2026-11-15):

- ~~ghcr.io visibility not confirmed~~: the image is public; an anonymous pull of the `0.1.0` manifest returns 200.
- ~~Release `assets` job never run~~: it ran on `v0.1.0` and passed (assets listed under "Current state").
- ~~`docker compose up` not exercised~~: run on Docker 29.7 / Compose 5.3 with image `0.1.0`, all three profiles:
  - default: `/api/health` ok, login link in the logs, token login, masked preview (user, internal IP and FQDN replaced), CSRF enforced (403 without the header), wrong `Host` rejected (421); container is read-only, `cap_drop: ALL`, uid 65532.
  - `tls` (`SUDARE_TLS=internal`, `SUDARE_DOMAIN=localhost`): HTTPS through Caddy, HSTS set, `:80` redirects to `https://`; the copied root certificate verifies the chain (OpenSSL). Windows curl (Schannel) rejects it with "revocation status is unknown", since a private CA has no CRL; use `--ssl-no-revoke` there.
  - `ollama`: Sudare lists `ollama` as ready and local over the compose network; with no model pulled an analysis fails cleanly (502, "model 'qwen3:8b' not found"). A full local analysis was not run (the default `qwen3:8b` needs more memory than the 3.7 GiB test VM had).

Still open:

- The standalone Vercel page was checked by headers only, not in a browser (the same build passed the Gemini browser test on Pages).
- The `ollama/ollama` container itself tries to reach `ollama.com` at startup (model "cloud cache"). Sudare sends nothing, but on an air-gapped or egress-filtered host expect that call to fail, and block it at the network if "nothing leaves the network" must hold for every container.
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
6. ~~Check the ghcr.io package visibility; decide on tagging `v0.1.0`.~~ Done: public, and `v0.1.0` is released.
7. Delete build caches on the old machine only after step 3 passes (`target/` is ~16 GB, `fuzz/target` ~1 GB; both are gitignored and rebuildable; `fuzz/corpus` is gitignored too, so copy it if you want to keep the fuzzing progress).
