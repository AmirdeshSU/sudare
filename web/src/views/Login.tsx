import { useEffect, useState } from "react";
import { api, errorText } from "../api.ts";
import { fragmentToken } from "../text.ts";
import { ErrorBox } from "../ui.tsx";

export function Login({ mode, onDone }: { mode: "single" | "multi"; onDone: () => void }) {
  const [token, setToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function login(body: object) {
    setError(null);
    try {
      await api("/login", "POST", body);
      onDone();
    } catch (e) {
      setError(errorText(e));
    }
  }

  // The startup link carries the token in the fragment; drop it from history at once.
  useEffect(() => {
    const t = fragmentToken(location.hash);
    if (t) {
      history.replaceState(null, "", location.pathname);
      api("/login", "POST", { token: t }).then(onDone, (e) => setError(errorText(e)));
    }
  }, [onDone]);

  return (
    <section className="login">
      <h1>Sudare</h1>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void login(mode === "single" ? { token } : { username, password });
        }}
      >
        {mode === "single" ? (
          <label>
            Login token (printed by <code>sudare serve</code>)
            <input type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} autoFocus />
          </label>
        ) : (
          <>
            <label>
              Username
              <input autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
            </label>
            <label>
              Password
              <input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </label>
          </>
        )}
        <ErrorBox error={error} />
        <button className="primary" type="submit">
          Log in
        </button>
      </form>
      <p className="muted">
        Or try the <a href="#/playground">masking playground</a>: it runs in your browser and needs no login.
      </p>
    </section>
  );
}
