import { useEffect, useState } from "react";
import { api, errorText, go, type Provider, type Report as R, type Stored } from "../api.ts";
import { Badge, CloudConfirm, ErrorBox, Masked, ProviderPicker, T, needsConfirm } from "../ui.tsx";

const lines = (ls: number[]) => ls.map((l) => `L${l}`).join(", ");
const attackUrl = (id: string) => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

export function ReportBody({ r }: { r: R }) {
  const a = r.analysis;
  return (
    <>
      {r.warnings.length > 0 && (
        <ul className="warnings">
          {r.warnings.map((w, i) => (
            <li key={i}>
              <b>{w.code}</b>: <T>{w.detail}</T>
            </li>
          ))}
        </ul>
      )}
      {a ? (
        <>
          <div className="row">
            <Badge kind={a.verdict}>{a.verdict}</Badge>
            <Badge kind={a.severity.level}>{a.severity.level}</Badge>
            <span>confidence {a.confidence.score.toFixed(2)}</span>
          </div>
          <p className="summary">
            <T>{a.summary}</T>
          </p>
          <h2>Severity</h2>
          <p>
            <T>{a.severity.rationale}</T>
          </p>
          <p className="muted">
            What would change the confidence: <T>{a.confidence.would_change_it}</T>
          </p>
          {a.timeline.length > 0 && (
            <>
              <h2>Timeline</h2>
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Event</th>
                    <th>Lines</th>
                  </tr>
                </thead>
                <tbody>
                  {a.timeline.map((t, i) => (
                    <tr key={i}>
                      <td className="nowrap">{t.timestamp ?? ""}</td>
                      <td>
                        <T>{t.description}</T>
                      </td>
                      <td>{lines(t.source_lines)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
          {a.entities.length > 0 && (
            <>
              <h2>Entities</h2>
              <table>
                <thead>
                  <tr>
                    <th>Entity</th>
                    <th>Role</th>
                    <th>Note</th>
                  </tr>
                </thead>
                <tbody>
                  {a.entities.map((e, i) => (
                    <tr key={i}>
                      <td>
                        <code>
                          <T>{e.ref}</T>
                        </code>
                      </td>
                      <td>
                        <T>{e.role}</T>
                      </td>
                      <td>
                        <T>{e.note}</T>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
          {a.attack_techniques.length > 0 && (
            <>
              <h2>ATT&amp;CK techniques</h2>
              <ul>
                {a.attack_techniques.map((t) => (
                  <li key={t.id}>
                    <a href={attackUrl(t.id)} target="_blank" rel="noreferrer noopener">
                      {t.id}
                    </a>{" "}
                    {t.name}: <T>{t.evidence}</T> <span className="muted">{lines(t.evidence_lines)}</span>
                  </li>
                ))}
              </ul>
              <p className="muted small">MITRE ATT&amp;CK® {r.meta.attack_version}, © The MITRE Corporation.</p>
            </>
          )}
          <h2>Recommended actions</h2>
          {(
            [
              ["Containment", a.recommended_actions.containment],
              ["Eradication", a.recommended_actions.eradication],
            ] as const
          ).map(([title, items]) =>
            items.length ? (
              <div key={title}>
                <h3>{title}</h3>
                <ul>
                  {items.map((x, i) => (
                    <li key={i}>
                      <T>{x}</T>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null,
          )}
          {a.recommended_actions.investigation.length > 0 && <h3>Investigation</h3>}
          {a.recommended_actions.investigation.map((q, i) => (
            <div key={i}>
              <p>
                <T>{q.purpose}</T> <span className="muted">({q.language})</span>
              </p>
              <pre>{q.query}</pre>
            </div>
          ))}
          {a.open_questions.length > 0 && (
            <>
              <h2>Open questions</h2>
              <ul>
                {a.open_questions.map((q, i) => (
                  <li key={i}>
                    <T>{q}</T>
                  </li>
                ))}
              </ul>
            </>
          )}
        </>
      ) : (
        <>
          <p className="error">The model never returned valid JSON. Its raw reply:</p>
          <pre>
            <T>{r.raw_output ?? ""}</T>
          </pre>
        </>
      )}
      {r.entities.length > 0 && (
        <>
          <h2>Indicators found by Sudare</h2>
          <table>
            <thead>
              <tr>
                <th>Value</th>
                <th>Type</th>
                <th>Scope</th>
                <th>Sent as</th>
                <th>Threat intel</th>
              </tr>
            </thead>
            <tbody>
              {r.entities.map((e, i) => (
                <tr key={i}>
                  <td>
                    <code>
                      <T>{e.value}</T>
                    </code>
                  </td>
                  <td>{e.kind}</td>
                  <td>{e.scope}</td>
                  <td>{e.token ? <code>{e.token}</code> : e.action}</td>
                  <td>
                    {e.enrichment.map((x, j) => (
                      <div key={j}>
                        {x.provider}: {x.verdict ?? x.status.replace(/_/g, " ")}
                        {x.score !== null && ` (${x.score})`}
                        {x.cached && <span className="muted"> cached</span>}
                        {x.link?.startsWith("https://") && (
                          <>
                            {" "}
                            <a href={x.link} target="_blank" rel="noreferrer noopener">
                              open
                            </a>
                          </>
                        )}
                      </div>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  );
}

function Chat({ id, initial, providers }: { id: string; initial: Stored["chat"]; providers: Provider[] }) {
  const [turns, setTurns] = useState(initial);
  const [question, setQuestion] = useState("");
  const [provider, setProvider] = useState(providers.find((p) => p.ready)?.name ?? "ollama");
  const [model, setModel] = useState("");
  const [pending, setPending] = useState<{ masked: string; digest: string } | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = providers.find((p) => p.name === provider);

  async function ask() {
    setBusy(true);
    setError(null);
    try {
      if (needsConfirm(current) && !pending) {
        const p = await api<{ masked_question: string; digest: string }>(`/analyses/${id}/chat/preview`, "POST", { question });
        setPending({ masked: p.masked_question, digest: p.digest });
        setConfirmed(false);
        return;
      }
      const r = await api<{ answer: string }>(`/analyses/${id}/chat`, "POST", {
        question,
        provider,
        model: model || null,
        confirm_digest: pending?.digest ?? null,
      });
      setTurns((t) => [...t, { question, answer: r.answer }]);
      setQuestion("");
      setPending(null);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2>Follow-up</h2>
      {turns.map((t, i) => (
        <div key={i} className="turn">
          <p className="q">
            <T>{t.question}</T>
          </p>
          <p className="a">
            <T>{t.answer}</T>
          </p>
        </div>
      ))}
      <textarea
        value={question}
        onChange={(e) => {
          setQuestion(e.target.value);
          setPending(null);
        }}
        placeholder="Ask about this incident…"
        aria-label="Question"
        rows={3}
      />
      <ProviderPicker
        providers={providers}
        value={provider}
        onChange={(p) => {
          setProvider(p);
          setPending(null);
        }}
        model={model}
        onModel={setModel}
      />
      {pending && (
        <>
          <p className="muted">This exact text will be sent:</p>
          <pre className="masked">
            <Masked text={pending.masked} />
          </pre>
          <CloudConfirm provider={current} checked={confirmed} onChange={setConfirmed} what="the masked question" />
        </>
      )}
      <ErrorBox error={error} />
      <button
        className="primary"
        disabled={busy || !question.trim() || !current?.ready || (pending !== null && !confirmed)}
        onClick={() => void ask()}
      >
        {busy ? "Working…" : needsConfirm(current) && !pending ? "Preview question" : "Ask"}
      </button>
    </section>
  );
}

export function Report({ id, providers }: { id: string; providers: Provider[] }) {
  const [data, setData] = useState<Stored | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Stored>(`/analyses/${id}`).then(setData, (e) => setError(errorText(e)));
  }, [id]);

  async function remove() {
    if (!window.confirm("Delete this analysis, its masked input and its sealed mask map?")) return;
    try {
      await api(`/analyses/${id}`, "DELETE");
      go("#/history");
    } catch (e) {
      setError(errorText(e));
    }
  }

  if (error) return <ErrorBox error={error} />;
  if (!data) return <p className="muted">Loading…</p>;
  const m = data.report.meta;
  return (
    <article>
      <h1>Incident analysis</h1>
      <p className="muted">
        {new Date(data.created_at * 1000).toLocaleString()} · {m.provider} {m.model} · {m.mode} mode · {m.parser} · {m.lines}{" "}
        lines
      </p>
      <ReportBody r={data.report} />
      <details>
        <summary>Masked input as sent</summary>
        <pre className="masked">
          <Masked text={data.masked_input} />
        </pre>
      </details>
      <Chat id={id} initial={data.chat} providers={providers} />
      <p>
        <button className="danger" onClick={() => void remove()}>
          Delete analysis
        </button>
      </p>
    </article>
  );
}
