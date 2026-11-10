import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The server embeds dist/ (rust-embed). In debug builds it reads dist/ from disk, so
// `npm run watch` + `cargo run -p sudare-cli -- serve` is the dev loop: no proxy.
export default defineConfig({
  plugins: [react()],
  build: {
    // The CSP allows no inline script.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
