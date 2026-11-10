import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { Standalone } from "./views/Standalone.tsx";
import "./styles.css";

// Standalone build (VITE_STANDALONE=1, for Vercel / Pages / any static host): the whole
// analysis in the browser, no Sudare server. Vite drops App from that bundle.
const standalone = import.meta.env.VITE_STANDALONE === "1";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {standalone ? (
      <main>
        <Standalone />
        <p className="muted">
          Sudare is open source: <a href="https://github.com/AmirdeshSU/sudare">github.com/AmirdeshSU/sudare</a>. For a team
          server with history, users and SIEM connectors, run it on-prem.
        </p>
      </main>
    ) : (
      <App />
    )}
  </StrictMode>,
);
