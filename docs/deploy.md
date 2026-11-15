# Deploying Sudare

Two ways to run it. Pick by where the logs may go.

| | Standalone (browser only) | On-prem server |
|---|---|---|
| Where it runs | Static site (Vercel, GitHub Pages, any static host) | Docker on your own host |
| Masking | In the browser tab (WebAssembly) | On the server |
| LLM call | Browser to the provider, with the visitor's own API key | Server to the provider, or to a local Ollama |
| Accounts, history, SIEM connectors | No | Yes |
| Air-gapped | Only with local Ollama | Yes |

Both mask before anything leaves the machine, and neither sends your logs to a Sudare-run service. There is none.

## Standalone

Live: https://amirdeshsu.github.io/sudare/ (GitHub Pages) and the Vercel deploy of the same build.

Build it yourself:

```sh
cd web
npm ci
npm run wasm                 # needs rustup target wasm32-unknown-unknown and wasm-bindgen-cli 0.2.130
npm run build:standalone     # output: web/dist-standalone
```

Serve `dist-standalone/` from any static host. The build embeds a Content-Security-Policy `<meta>`: scripts and WebAssembly from the same origin, and `connect-src` limited to Gemini, OpenAI, Anthropic and `http://127.0.0.1:11434`. Behind your own server, also send the headers from `web/vercel.json` (including `frame-ancestors 'none'`).

API keys stay in the visitor's browser (`sessionStorage`; `localStorage` only if they tick "Remember"). Keys go in request headers, never URLs.

Local Ollama from the standalone page: start it with `OLLAMA_ORIGINS=<the page origin>`.

### Vercel

Project settings: root directory `web`, install `npm ci --no-audit --no-fund`, build `bash vercel-build.sh`, output `dist-standalone`. The build script installs Rust and a sha256-checked wasm-bindgen, so the first build takes a few minutes.

## On-prem

Needs Docker with Compose. Nothing else.

```sh
cp deploy/.env.example deploy/.env
docker run --rm ghcr.io/amirdeshsu/sudare:edge keygen      # paste into SUDARE_SECRET_KEY
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs sudare    # single-user login link
```

Sudare listens on `127.0.0.1:8080` only. Profiles:

- `--profile tls`: Caddy on :443 in front of it.
- `--profile ollama`: a local model server. Pull a model with `docker compose exec ollama ollama pull <model>`.

### TLS

Set in `deploy/.env`, and use `--profile tls`:

- `SUDARE_DOMAIN`: the name clients use.
- `SUDARE_TLS=internal`: Caddy's own CA. Install its root certificate on clients (`docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt .`).
- `SUDARE_TLS=you@example.com`: Let's Encrypt. Needs public DNS and port 80.
- `SUDARE_TLS=/certs/fullchain.pem /certs/privkey.pem`: your own CA. Put the files in `deploy/certs/`.

With TLS also set `SUDARE_ALLOWED_HOSTS=<domain>` and `SUDARE_COOKIE_SECURE=true`.

### Multi-user

`SUDARE_MODE=multi` and `SUDARE_ADMIN_PASSWORD` (12+ chars) for the first admin. Create the other accounts in Settings.

### Air-gapped

On a connected machine:

```sh
docker pull ghcr.io/amirdeshsu/sudare:0.1.0 && docker pull ollama/ollama:0.40.13 && docker pull caddy:2.10.2
docker save -o sudare-images.tar ghcr.io/amirdeshsu/sudare:0.1.0 ollama/ollama:0.40.13 caddy:2.10.2
```

Carry `sudare-images.tar`, `deploy/` and the model files across. On the isolated host: `docker load -i sudare-images.tar`, set `SUDARE_VERSION=0.1.0`, then `docker compose --profile ollama up -d`. The server only calls hosts you configure; with Ollama as the only provider, nothing leaves the network.

### Upgrade and backup

```sh
docker compose -f deploy/docker-compose.yml pull && docker compose -f deploy/docker-compose.yml up -d
```

State is the `sudare-data` volume (encrypted with `SUDARE_SECRET_KEY`; keep the key backed up separately, since without it the data is unreadable). To build from a checkout instead: `up -d --build`.
