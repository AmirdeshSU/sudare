import { useEffect, useRef, useState } from "react";
import { errorText, type Provider, type Report, type Stats } from "../api.ts";
import { complete, PROVIDERS, type Kind, type Msg } from "../providers.ts";
import { CloudConfirm, Diff, ErrorBox, Masked, StatChips, T } from "../ui.tsx";
import { SAMPLE } from "./Playground.tsx";
import { ReportBody } from "./Report.tsx";

// The whole analysis in this tab: wasm masks, the browser calls the provider with the
// visitor's own key, wasm unmasks. There is no Sudare server in this build.

type Wasm = typeof import("../wasm/sudare_wasm.js");
type Session = InstanceType<Wasm["Session"]>;
type Preview = { masked: string; parser: string; lines: number; events: number; stats: Stats; public_indicators: number };

// Keys stay in this browser: sessionStorage by default, localStorage when remembered.
const keyName = (k: Kind) => `sudare.key.${k}`;
function loadKey(k: Kind): string {
  try {
    return localStorage.getItem(keyName(k)) ?? sessionStorage.getItem(keyName(k)) ?? "";
  } catch {
    return "";
  }
}
function saveKey(k: Kind, key: string, remember: boolean) {
  try {
    sessionStorage.setItem(keyName(k), key);
    if (remember) localStorage.setItem(keyName(k), key);
    else localStorage.removeItem(keyName(k));
  } catch {
    // storage blocked: the key just isn't kept
  }
}
const remembered = (k: Kind) => {
  try {
    return localStorage.getItem(keyName(k)) !== null;
  } catch {
    return false;
  }
};

export function Standalone() {
  const [wasm, setWasm] = useState<Wasm | null>(null);
  const session = useRef<Session | null>(null);
  const [text, setText] = useState(SAMPLE);
  const [parser, setParser] = useState("");
  const [parsers, setParsers] = useState<{ name: string; description: string }[]>([]);
  const [strict, setStrict] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [kind, setKind] = useState<Kind>("gemini");
  const [key, setKey] = useState(() => loadKey("gemini"));
  const [remember, setRemember] = useState(() => remembered("gemini"));
  const [model, setModel] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [turns, setTurns] = useState<{ question: string; answer: string }[]>([]);
  const [question, setQuestion] = useState("");
  const [pending, setPending] = useState<{ question: string; messages: Msg[] } | null>(null);
  const [qConfirmed, setQConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    import("../wasm/sudare_wasm.js")
      .then(async (m) => {
        await m.default();
        setParsers(JSON.parse(m.parsers()) as typeof parsers);
        setWasm(m);
      })
      .catch((e) => setError(`Could not load the WebAssembly engine: ${errorText(e)}`));
    return () => session.current?.free();
  }, []);

  const spec = PROVIDERS[kind];
  const provider: Provider = { name: spec.label, ready: true, local: spec.local, model: spec.model, base_url: spec.base };
  const needsKey = !spec.local;
  const usedModel = model.trim() || spec.model;

  function pick(k: Kind) {
    setKind(k);
    setKey(loadKey(k));
    setRemember(remembered(k));
    setModel("");
    setConfirmed(false);
    setPending(null);
  }

  function reset() {
    session.current?.free();
    session.current = null;
    setPreview(null);
    setReport(null);
    setTurns([]);
    setPending(null);
    setConfirmed(false);
    setError(null);
  }

  function doPreview() {
    if (!wasm) return;
    setError(null);
    try {
      session.current?.free();
      // A fresh salt per analysis: token numbers never repeat across runs.
      const s = new wasm.Session(text, strict, parser || undefined, crypto.getRandomValues(new Uint8Array(32)));
      session.current = s;
      setPreview(JSON.parse(s.preview()) as Preview);
      setConfirmed(false);
    } catch (e) {
      setError(errorText(e));
    }
  }

  async function analyze() {
    const s = session.current;
    if (!s) return;
    setBusy(true);
    setError(null);
    try {
      if (needsKey) saveKey(kind, key.trim(), remember);
      const p = JSON.parse(s.analysis_prompt(spec.context, undefined, undefined)) as { messages: Msg[]; schema: unknown };
      let r = await complete(kind, key.trim(), usedModel, p.messages, p.schema);
      const again = s.retry_prompt(r.text);
      if (again) r = await complete(kind, key.trim(), usedModel, JSON.parse(again) as Msg[], p.schema);
      setReport(JSON.parse(s.finish(r.text, kind, r.model, Date.now() / 1000)) as Report);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function ask() {
    const s = session.current;
    if (!s) return;
    setBusy(true);
    setError(null);
    try {
      let p = pending;
      if (!p) {
        p = JSON.parse(s.chat_prompt(question, spec.context)) as { question: string; messages: Msg[] };
        if (!spec.local) {
          setPending(p);
          setQConfirmed(false);
          return;
        }
      }
      const r = await complete(kind, key.trim(), usedModel, p.messages);
      setTurns((t) => [...t, { question, answer: s.chat_answer(r.text) }]);
      setQuestion("");
      setPending(null);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  const providerPicker = (
    <div className="row">
      <label>
        Provider
        <select value={kind} onChange={(e) => pick(e.target.value as Kind)}>
          {(Object.keys(PROVIDERS) as Kind[]).map((k) => (
            <option key={k} value={k}>
              {PROVIDERS[k].label}
            </option>
          ))}
        </select>
      </label>
      <label>
        Model
        <input value={model} placeholder={spec.model} onChange={(e) => setModel(e.target.value)} />
      </label>
      {needsKey && (
        <label>
          API key (<a href={spec.keyHelp}>get one</a>)
          <input type="password" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" spellCheck={false} />
        </label>
      )}
      {needsKey && (
        <label className="inline">
          <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} /> Remember the key on this
          device
        </label>
      )}
    </div>
  );

  if (report) {
    return (
      <article>
        <h1>Incident analysis</h1>
        <p className="muted">
          {spec.label} {report.meta.model} · {report.meta.mode} mode · {report.meta.parser} · {report.meta.lines} lines
        </p>
        <ReportBody r={report} />
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
          {pending && (
            <>
              <p className="muted">This exact text will be sent:</p>
              <pre className="masked">
                <Masked text={pending.question} />
              </pre>
              <CloudConfirm provider={provider} checked={qConfirmed} onChange={setQConfirmed} what="the masked question" />
            </>
          )}
          <ErrorBox error={error} />
          <button
            className="primary"
            disabled={busy || !question.trim() || (pending !== null && !qConfirmed)}
            onClick={() => void ask()}
          >
            {busy ? "Working…" : !spec.local && !pending ? "Preview question" : "Ask"}
          </button>
        </section>
        <p>
          <button onClick={reset}>New analysis</button>
        </p>
      </article>
    );
  }

  if (preview) {
    return (
      <section>
        <h1>Review what will be sent</h1>
        <StatChips stats={preview.stats} />
        <p className="muted">
          {preview.parser} · {preview.lines} lines · {preview.events} events. Left: what you pasted. Right: what{" "}
          {spec.local ? "your local model" : spec.label} receives, straight from this browser.
        </p>
        <Diff original={text} masked={preview.masked} />
        {providerPicker}
        <CloudConfirm provider={provider} checked={confirmed} onChange={setConfirmed} what="the masked logs" />
        <ErrorBox error={error} />
        <div className="row">
          <button onClick={reset} disabled={busy}>
            Back
          </button>
          <button
            className="primary"
            disabled={busy || (needsKey && !key.trim()) || (!spec.local && !confirmed)}
            onClick={() => void analyze()}
          >
            {busy ? "Analysing…" : "Analyse"}
          </button>
        </div>
      </section>
    );
  }

  return (
    <section>
      <h1>New analysis</h1>
      <p className="note">
        Everything runs in this tab. Sensitive values are masked here (WebAssembly), the masked text goes straight from your
        browser to the model you pick with your own key, and real values are restored here. This site has no server and stores
        nothing.
      </p>
      <textarea
        className="logs"
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        aria-label="Logs"
        placeholder="Paste syslog, CEF, LEEF, Windows XML, JSON or plain text…"
      />
      <div className="row">
        <label>
          File
          <input type="file" onChange={(e) => void e.target.files?.[0]?.text().then(setText)} />
        </label>
        <label>
          Parser
          <select value={parser} onChange={(e) => setParser(e.target.value)}>
            <option value="">auto-detect</option>
            {parsers.map((p) => (
              <option key={p.name} value={p.name} title={p.description}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <label className="inline">
          <input type="checkbox" checked={strict} onChange={(e) => setStrict(e.target.checked)} /> Strict mode (mask public IOCs
          too)
        </label>
      </div>
      <ErrorBox error={error} />
      <button className="primary" disabled={!wasm || !text.trim()} onClick={doPreview}>
        {wasm ? "Preview masking" : "Loading engine…"}
      </button>
    </section>
  );
}
