# Build from the repo root:  docker build -f deploy/Dockerfile -t sudare .
# 1. The masking engine as WebAssembly, for the browser playground.
FROM rust:1.99.1-slim-trixie AS wasm
WORKDIR /src
RUN rustup target add wasm32-unknown-unknown \
 && cargo install wasm-bindgen-cli --version 0.2.130 --locked
COPY . .
RUN cargo build --release --locked -p sudare-wasm --target wasm32-unknown-unknown --config profile.release.strip=false \
 && wasm-bindgen --target web --out-dir /wasm target/wasm32-unknown-unknown/release/sudare_wasm.wasm

# 2. The web UI.
FROM node:24.18.0-trixie-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
COPY --from=wasm /wasm src/wasm
RUN npm run build

# 3. The server binary, with the UI embedded.
FROM wasm AS build
COPY --from=web /web/dist web/dist
RUN cargo build --release --locked -p sudare-cli \
 && mkdir -p /out/data && cp target/release/sudare /out/sudare

# distroless/cc: glibc, CA certificates (for rustls' OS trust store), no shell.
FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=build /out/sudare /sudare
# The volume mounted here inherits this ownership on first use.
COPY --from=build --chown=65532:65532 /out/data /data
ENV SUDARE_BIND=0.0.0.0:8080 \
    SUDARE_DATA_DIR=/data \
    SUDARE_ALLOWED_HOSTS=localhost:8080,127.0.0.1:8080
USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/sudare"]
CMD ["serve"]
