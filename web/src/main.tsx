import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { Playground } from "./views/Playground.tsx";
import "./styles.css";

// GitHub Pages build (VITE_PAGES=1): the playground only. Vite drops App from the bundle.
const pages = import.meta.env.VITE_PAGES === "1";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {pages ? (
      <main>
        <p className="muted">
          Sudare masks sensitive values in security logs before an LLM sees them. This demo runs the masking engine in
          your browser; nothing you paste is sent anywhere. To analyse logs, self-host it:{" "}
          <a href="https://github.com/AmirdeshSU/sudare">github.com/AmirdeshSU/sudare</a>
        </p>
        <Playground />
      </main>
    ) : (
      <App />
    )}
  </StrictMode>,
);
