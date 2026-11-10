import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// VITE_PAGES=1 builds the static playground for GitHub Pages: no server, so the CSP
// the server sends as a header goes in a meta tag instead (frame-ancestors can't).
const pages = process.env.VITE_PAGES === "1";
const pagesCsp: Plugin = {
  name: "pages-csp",
  transformIndexHtml: () => [
    {
      tag: "meta",
      attrs: {
        "http-equiv": "Content-Security-Policy",
        content:
          "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'",
      },
      injectTo: "head-prepend",
    },
  ],
};

// The server embeds dist/ (rust-embed). In debug builds it reads dist/ from disk, so
// `npm run watch` + `cargo run -p sudare-cli -- serve` is the dev loop: no proxy.
export default defineConfig({
  plugins: pages ? [react(), pagesCsp] : [react()],
  build: {
    // The CSP allows no inline script.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
