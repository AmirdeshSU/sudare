import { useEffect, useState } from "react";
import { api, errorText, type Summary } from "../api.ts";
import { Badge, ErrorBox, T } from "../ui.tsx";

export function History() {
  const [rows, setRows] = useState<Summary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<Summary[]>("/analyses").then(setRows, (e) => setError(errorText(e)));
  }, []);

  if (error) return <ErrorBox error={error} />;
  if (!rows) return <p className="muted">Loading…</p>;
  return (
    <section>
      <h1>History</h1>
      {rows.length === 0 ? (
        <p className="muted">
          No analyses yet. <a href="#/">Start one</a>.
        </p>
      ) : (
        <table className="history">
          <thead>
            <tr>
              <th>When</th>
              <th>Verdict</th>
              <th>Severity</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="nowrap">
                  <a href={`#/a/${r.id}`}>{new Date(r.created_at * 1000).toLocaleString()}</a>
                </td>
                <td>{r.verdict ? <Badge kind={r.verdict}>{r.verdict}</Badge> : "no verdict"}</td>
                <td>{r.severity ? <Badge kind={r.severity}>{r.severity}</Badge> : ""}</td>
                <td>
                  <T>{r.summary ?? ""}</T>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
