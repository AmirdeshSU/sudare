import { useCallback, useEffect, useState } from "react";
import { api, go, LOGGED_OUT, type Me, type Provider } from "./api.ts";
import { route } from "./text.ts";
import { Analyze } from "./views/Analyze.tsx";
import { History } from "./views/History.tsx";
import { Login } from "./views/Login.tsx";
import { Playground } from "./views/Playground.tsx";
import { Report } from "./views/Report.tsx";
import { Settings } from "./views/Settings.tsx";

type Ctx = { me: Me; parsers: { name: string; description: string }[]; providers: Provider[] };

/** Session context, or the login mode when there is no session. */
async function fetchCtx(): Promise<[Ctx | null, "single" | "multi"]> {
  try {
    const me = await api<Me>("/me");
    const [parsers, providers] = await Promise.all([api<Ctx["parsers"]>("/parsers"), api<Provider[]>("/providers")]);
    return [{ me, parsers, providers }, me.mode];
  } catch {
    const h = await api<{ mode: "single" | "multi" }>("/health").catch(() => ({ mode: "single" as const }));
    return [null, h.mode];
  }
}

function useHash() {
  const [hash, setHash] = useState(location.hash);
  useEffect(() => {
    const on = () => setHash(location.hash);
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return hash;
}

export function App() {
  const hash = useHash();
  const [ctx, setCtx] = useState<Ctx | null>(null);
  const [mode, setMode] = useState<"single" | "multi" | null>(null);

  const load = useCallback(
    () =>
      fetchCtx().then(([c, m]) => {
        setCtx(c);
        setMode(m);
      }),
    [],
  );

  useEffect(() => {
    void load();
    const out = () => setCtx(null);
    window.addEventListener(LOGGED_OUT, out);
    return () => window.removeEventListener(LOGGED_OUT, out);
  }, [load]);

  const [page, arg] = route(hash);

  async function logout() {
    await api("/logout", "POST").catch(() => undefined);
    setCtx(null);
    go("#/");
  }

  let body;
  if (page === "playground") body = <Playground />;
  else if (!ctx) body = mode ? <Login mode={mode} onDone={load} /> : <p className="muted">Loading…</p>;
  else if (page === "history") body = <History />;
  else if (page === "settings") body = <Settings me={ctx.me} />;
  else if (page === "a" && arg) body = <Report key={arg} id={arg} providers={ctx.providers} />;
  else body = <Analyze parsers={ctx.parsers} providers={ctx.providers} />;

  const link = (href: string, label: string, active: boolean) => (
    <a href={href} aria-current={active ? "page" : undefined}>
      {label}
    </a>
  );
  return (
    <>
      <header>
        <nav>
          <b className="brand">Sudare</b>
          {ctx && link("#/", "New analysis", !page)}
          {ctx && link("#/history", "History", page === "history" || page === "a")}
          {ctx && link("#/settings", "Settings", page === "settings")}
          {link("#/playground", "Playground", page === "playground")}
          {ctx && (
            <span className="right">
              {ctx.me.user.username}{" "}
              <button className="link" onClick={() => void logout()}>
                Log out
              </button>
            </span>
          )}
        </nav>
      </header>
      <main>{body}</main>
    </>
  );
}
