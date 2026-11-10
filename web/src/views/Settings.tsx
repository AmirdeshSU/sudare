import { useCallback, useEffect, useState } from "react";
import { api, errorText, type Key, type Me, type User } from "../api.ts";
import { ErrorBox } from "../ui.tsx";

function Keys() {
  const [keys, setKeys] = useState<Key[]>([]);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => api<Key[]>("/keys").then(setKeys, (e) => setError(errorText(e))), []);
  useEffect(() => void load(), [load]);

  async function save(name: string) {
    setError(null);
    try {
      await api(`/keys/${name}`, "PUT", { key: drafts[name] ?? "" });
      setDrafts((d) => ({ ...d, [name]: "" }));
      await load();
    } catch (e) {
      setError(errorText(e));
    }
  }
  async function remove(name: string) {
    await api(`/keys/${name}`, "DELETE").catch((e) => setError(errorText(e)));
    await load();
  }

  return (
    <section>
      <h2>API keys</h2>
      <p className="muted">
        Stored encrypted and never shown again; only the last four characters are kept as a hint. Keys set in the server's
        environment apply when you have none saved.
      </p>
      <ErrorBox error={error} />
      <table>
        <tbody>
          {keys.map((k) => (
            <tr key={k.name}>
              <td>
                {k.name} <span className="muted">{k.kind === "llm" ? "LLM" : "threat intel"}</span>
              </td>
              <td>{k.saved ? <code>{k.hint}</code> : <span className="muted">not saved</span>}</td>
              <td className="row">
                <input
                  type="password"
                  autoComplete="off"
                  aria-label={`${k.name} key`}
                  value={drafts[k.name] ?? ""}
                  onChange={(e) => setDrafts((d) => ({ ...d, [k.name]: e.target.value }))}
                />
                <button disabled={!drafts[k.name]} onClick={() => void save(k.name)}>
                  Save
                </button>
                {k.saved && (
                  <button className="danger" onClick={() => void remove(k.name)}>
                    Remove
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Retention({ admin }: { admin: boolean }) {
  const [days, setDays] = useState<number | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<{ retention_days: number }>("/settings").then((s) => setDays(s.retention_days), (e) => setError(errorText(e)));
  }, []);
  async function save() {
    setError(null);
    try {
      const r = await api<{ purged: number }>("/settings", "PUT", { retention_days: days });
      setMsg(`Saved. ${r.purged} older analyses removed.`);
    } catch (e) {
      setError(errorText(e));
    }
  }
  if (days === null) return <ErrorBox error={error} />;
  return (
    <section>
      <h2>Retention</h2>
      <div className="row">
        <label>
          Keep analyses for (days)
          <input type="number" min={1} max={3650} value={days} disabled={!admin} onChange={(e) => setDays(Number(e.target.value))} />
        </label>
        {admin && <button onClick={() => void save()}>Save</button>}
      </div>
      {msg && <p className="muted">{msg}</p>}
      <ErrorBox error={error} />
    </section>
  );
}

function Users({ me }: { me: User }) {
  const [users, setUsers] = useState<User[]>([]);
  const [form, setForm] = useState({ username: "", password: "", admin: false });
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => api<User[]>("/users").then(setUsers, (e) => setError(errorText(e))), []);
  useEffect(() => void load(), [load]);

  async function create() {
    setError(null);
    try {
      await api("/users", "POST", form);
      setForm({ username: "", password: "", admin: false });
      await load();
    } catch (e) {
      setError(errorText(e));
    }
  }
  async function remove(u: User) {
    if (!window.confirm(`Delete ${u.username} and all of their analyses and keys?`)) return;
    await api(`/users/${u.id}`, "DELETE").catch((e) => setError(errorText(e)));
    await load();
  }

  return (
    <section>
      <h2>Users</h2>
      <table>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.username}</td>
              <td>{u.role}</td>
              <td>
                {u.id !== me.id && (
                  <button className="danger" onClick={() => void remove(u)}>
                    Delete
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="row">
        <input placeholder="username" aria-label="New username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
        <input
          type="password"
          placeholder="password (12+ characters)"
          aria-label="New password"
          autoComplete="new-password"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
        />
        <label className="inline">
          <input type="checkbox" checked={form.admin} onChange={(e) => setForm({ ...form, admin: e.target.checked })} /> admin
        </label>
        <button disabled={!form.username || !form.password} onClick={() => void create()}>
          Add user
        </button>
      </div>
      <ErrorBox error={error} />
    </section>
  );
}

export function Settings({ me }: { me: Me }) {
  const admin = me.user.role === "admin";
  return (
    <>
      <h1>Settings</h1>
      <Keys />
      <Retention admin={admin} />
      {me.mode === "multi" && admin && <Users me={me.user} />}
    </>
  );
}
