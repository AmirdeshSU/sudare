# Operations

Install, TLS, air-gapped and upgrade steps are in [deploy.md](deploy.md). This page covers what runs where and routine care.

## What is deployed

| Piece | Where | How it updates |
|---|---|---|
| Standalone app (Vercel) | project `sudare`, Vercel team `amir61`, https://sudare-amir61.vercel.app | Git-linked: every push to `main` deploys to production. Build: `web/vercel-build.sh` (installs Rust and a sha256-pinned wasm-bindgen). Vercel login protection is **off** (public site). |
| Standalone app (GitHub Pages) | https://amirdeshsu.github.io/sudare/ | `.github/workflows/pages.yml` on every push to `main` |
| Container image | `ghcr.io/amirdeshsu/sudare` (`edge` = main, `X.Y.Z` on tags) | `.github/workflows/release.yml` |
| GitHub Release assets (binary, static bundle, SHA256SUMS) | GitHub Releases | only on a `vX.Y.Z` tag; **never run yet** |
| On-prem server | whoever runs `deploy/docker-compose.yml` | `docker compose pull && up -d` |

There is no Sudare-run backend service, database or telemetry. The standalone app has no server state at all.

## Server (on-prem) state

- Data: the `sudare-data` volume (`/data`): one SQLite file, mode 0600. Contains masked inputs, reports, and mask maps and API keys sealed with `SUDARE_SECRET_KEY`.
- **Back up** the volume and `SUDARE_SECRET_KEY` separately. Without the key the sealed data is unreadable; with both, restore = recreate the volume and set the same key.
- Backup example: `docker run --rm -v deploy_sudare-data:/data -v "$PWD":/b busybox tar czf /b/sudare-data.tgz -C /data .` (*unverified*; the volume name depends on the compose project name).
- Retention: `SUDARE_RETENTION_DAYS` (default 30); deleting an analysis removes input, result and map together.
- Health: `GET /api/health`. Logs: `docker compose logs sudare` (single-user login link is printed at startup).
- Rotating the secret key: no tooling exists in the code (none found). Data sealed with the old key becomes unreadable, so re-enter provider keys and treat old history as lost.

## Routine tasks

| Task | Command |
|---|---|
| Upgrade | `docker compose -f deploy/docker-compose.yml pull && docker compose -f deploy/docker-compose.yml up -d` |
| Pin a version | `SUDARE_VERSION=0.1.0` in `deploy/.env` |
| Refresh ATT&CK index (maintainers, when MITRE releases) | `python3 scripts/update_attack_index.py enterprise-attack.json` |
| Re-run all checks | push to `main` or open a PR; see CI |
| Add a provider origin to the standalone app | edit the CSP in `web/vite.config.ts` and `web/vercel.json`, then push |
| Cut a release | `git tag v0.1.0 && git push --tags` (exercises the `assets` job for the first time) |

## Monitoring

None configured. Vercel Analytics is off by design. Failed deploys show in the Vercel dashboard (project `sudare`) and in GitHub Actions.

## Recovery

- Bad standalone deploy: Vercel dashboard, Deployments, "Promote" a previous one (or `git revert` and push).
- Bad image: pin `SUDARE_VERSION` to the last good tag/digest and `up -d`.
- Lost server host: restore the volume backup and `deploy/.env` on a new host, then `up -d`.
