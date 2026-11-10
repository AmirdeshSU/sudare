#!/usr/bin/env bash
# Vercel build for the standalone app. Vercel's image has no Rust: install a minimal
# toolchain and a pinned, checksum-verified wasm-bindgen, then build wasm + the app.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi
rustup target add wasm32-unknown-unknown

V=0.2.130
SHA=9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f
if [ "$(wasm-bindgen --version 2>/dev/null)" != "wasm-bindgen $V" ]; then
  T=$(mktemp -d)
  curl -sSfL -o "$T/wb.tgz" "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/$V/wasm-bindgen-$V-x86_64-unknown-linux-musl.tar.gz"
  echo "$SHA  $T/wb.tgz" | sha256sum -c -
  tar xzf "$T/wb.tgz" -C "$T"
  export PATH="$T/wasm-bindgen-$V-x86_64-unknown-linux-musl:$PATH"
fi

npm run wasm
npm run build:standalone
