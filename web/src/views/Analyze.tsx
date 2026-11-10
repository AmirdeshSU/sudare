import { useState } from "react";
import { api, ApiError, errorText, go, type Preview, type Provider } from "../api.ts";
import { CloudConfirm, Diff, ErrorBox, Masked, ProviderPicker, StatChips, needsConfirm } from "../ui.tsx";

const MAX_BYTES = 16 * 1024 * 1024;

export function Analyze(props: { parsers: { name: string; description: string }[]; providers: Provider[] }) {
  const [text, setText] = useState("");
  const [parser, setParser] = useState("");
  const [strict, setStrict] = useState(false);
  const [preview, setPreview] = useState<Preview | null>(null);
  const firstReady = props.providers.find((p) => p.ready)?.name ?? "ollama";
  const [provider, setProvider] = useState(firstReady);
  const [model, setModel] = useState("");
  const [enrich, setEnrich] = useState(true);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const current = props.providers.find((p) => p.name === provider);

  async function loadFile(f: File | undefined) {
    if (!f) return;
    if (f.size > MAX_BYTES) return setError("File is over 16 MiB.");
    setText(await f.text());
  }

  async function doPreview() {
    setBusy(true);
    setError(null);
    try {
      setPreview(await api<Preview>("/preview", "POST", { text, strict, parser: parser || null }));
      setConfirmed(false);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function send() {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ id: string }>("/analyses", "POST", {
        preview_id: preview.preview_id,
        provider,
        model: model || null,
        enrich,
        confirm_digest: needsConfirm(current) && confirmed ? preview.digest : null,
      });
      go(`#/a/${r.id}`);
    } catch (e) {
      if (e instanceof ApiError && e.code === "preview_not_found") setPreview(null);
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  if (!preview) {
    return (
      <section>
        <h1>New analysis</h1>
        <p className="muted">
          Paste logs or open a file. Nothing is sent anywhere until you have reviewed the masked version.
        </p>
        <textarea
          className="logs"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste syslog, CEF, LEEF, Windows XML, JSON or plain text…"
          spellCheck={false}
          aria-label="Logs"
        />
        <div className="row">
          <label>
            File
            <input type="file" onChange={(e) => void loadFile(e.target.files?.[0])} />
          </label>
          <label>
            Parser
            <select value={parser} onChange={(e) => setParser(e.target.value)}>
              <option value="">auto-detect</option>
              {props.parsers.map((p) => (
                <option key={p.name} value={p.name} title={p.description}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <label className="inline">
            <input type="checkbox" checked={strict} onChange={(e) => setStrict(e.target.checked)} /> Strict mode (mask public
            IOCs too)
          </label>
        </div>
        <ErrorBox error={error} />
        <button className="primary" disabled={busy || !text.trim()} onClick={() => void doPreview()}>
          {busy ? "Masking…" : "Preview masking"}
        </button>
      </section>
    );
  }

  const blocked = needsConfirm(current) && !confirmed;
  return (
    <section>
      <h1>Review the masked logs</h1>
      <p className="muted">
        Parser <b>{preview.parser}</b> · {preview.lines} lines · {preview.events} events
        {preview.parse_errors > 0 && ` · ${preview.parse_errors} malformed`} · {preview.strict ? "strict" : "default"} mode
      </p>
      <StatChips stats={preview.stats} />
      {preview.kept_public_domains.length > 0 && (
        <div className="note">
          Kept as public (sent unmasked): {preview.kept_public_domains.join(", ")}. If any is yours, add it to the
          policy's internal domains or use strict mode.
        </div>
      )}
      <Diff original={text} masked={preview.masked} />
      <details>
        <summary>Full masked text ({preview.masked.length.toLocaleString()} characters)</summary>
        <pre className="masked">
          <Masked text={preview.masked} />
        </pre>
      </details>

      <h2>Send</h2>
      <ProviderPicker providers={props.providers} value={provider} onChange={(p) => { setProvider(p); setConfirmed(false); }} model={model} onModel={setModel} />
      <label className="inline">
        <input type="checkbox" checked={enrich} onChange={(e) => setEnrich(e.target.checked)} /> Look up the{" "}
        {preview.public_indicators} public indicators with threat-intel providers that have a key
      </label>
      <CloudConfirm provider={current} checked={confirmed} onChange={setConfirmed} what="the masked text above" />
      <ErrorBox error={error} />
      <div className="row">
        <button onClick={() => setPreview(null)} disabled={busy}>
          Back
        </button>
        <button className="primary" disabled={busy || blocked || !current?.ready} onClick={() => void send()}>
          {busy ? "Analyzing…" : "Analyze"}
        </button>
      </div>
    </section>
  );
}
