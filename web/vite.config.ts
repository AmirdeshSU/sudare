import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// VITE_STANDALONE=1 builds the serverless app (static hosting): the page calls LLM
// providers itself, so connect-src lists exactly those. The same policy goes out as an
// HTTP header where the host allows it (vercel.json), which can also set frame-ancestors.
const standalone = process.env.VITE_STANDALONE === "1";
const STANDALONE_CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self' https://generativelanguage.googleapis.com https://api.openai.com https://api.anthropic.com http://127.0.0.1:11434; " +
  "object-src 'none'; base-uri 'none'; form-action 'none'";
const standaloneCsp: Plugin = {
  name: "standalone-csp",
  transformIndexHtml: () => [
    {
      tag: "meta",
      attrs: {
        "http-equiv": "Content-Security-Policy",
        content: STANDALONE_CSP,
      },
      injectTo: "head-prepend",
    },
  ],
};

// The server embeds dist/ (rust-embed). In debug builds it reads dist/ from disk, so
// `npm run watch` + `cargo run -p sudare-cli -- serve` is the dev loop: no proxy.
export default defineConfig({
  plugins: standalone ? [react(), standaloneCsp] : [react()],
  build: {
    // The CSP allows no inline script.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
