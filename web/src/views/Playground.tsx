import { useEffect, useState } from "react";
import { errorText, type Stats } from "../api.ts";
import { Diff, ErrorBox, StatChips } from "../ui.tsx";

type Wasm = typeof import("../wasm/sudare_wasm.js");
type Decision = { entity: { value: string; kind: string | Record<string, string>; scope: string }; action: string; token: string | null };
type Result = { masked: string; parser: string; lines: number; events: number; stats: Stats; public_indicators: number; decisions: Decision[] };

export const SAMPLE = `<34>Oct 29 14:11:40 fw01 sshd[2211]: Failed password for jdoe from 198.51.100.23 port 51122 ssh2
<38>Oct 29 14:12:05 fw01 sshd[2211]: Accepted password for jdoe from 198.51.100.23 port 51130 ssh2
<13>Oct 29 14:13:00 ws-17.corp.example.com proxy: user=jdoe src=10.20.30.40 GET https://malware.example.org/payload.bin`;

const kindName = (k: Decision["entity"]["kind"]) => (typeof k === "string" ? k : Object.values(k)[0] ?? "custom");

export function Playground() {
  const [wasm, setWasm] = useState<Wasm | null>(null);
  const [text, setText] = useState(SAMPLE);
  const [strict, setStrict] = useState(false);
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    import("../wasm/sudare_wasm.js")
      .then(async (m) => {
        await m.default();
        setWasm(m);
      })
      .catch((e) => setError(`Could not load the WebAssembly engine: ${errorText(e)}`));
  }, []);

  function run() {
    if (!wasm) return;
    setError(null);
    try {
      // A fresh salt per run, as on the server: token numbers never repeat across runs.
      const salt = crypto.getRandomValues(new Uint8Array(32));
      setResult(JSON.parse(wasm.mask(text, strict, undefined, salt)) as Result);
    } catch (e) {
      setError(errorText(e));
    }
  }

  const rows = new Map<string, Decision>();
  for (const d of result?.decisions ?? []) rows.set(`${d.token ?? d.action}|${d.entity.value}`, d);

  return (
    <section>
      <h1>Masking playground</h1>
      <p className="note">
        Runs entirely in this browser tab (WebAssembly, the same engine as the server). Nothing is uploaded, stored or sent to a
        model. Use invented data anyway.
      </p>
      <textarea className="logs" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-label="Logs" />
      <div className="row">
        <label className="inline">
          <input type="checkbox" checked={strict} onChange={(e) => setStrict(e.target.checked)} /> Strict mode
        </label>
        <button className="primary" disabled={!wasm || !text.trim()} onClick={run}>
          {wasm ? "Mask" : "Loading engine…"}
        </button>
      </div>
      <ErrorBox error={error} />
      {result && (
        <>
          <p className="muted">
            Parser <b>{result.parser}</b> · {result.lines} lines · {result.events} events · {result.public_indicators} public
            indicators
          </p>
          <StatChips stats={result.stats} />
          <Diff original={text} masked={result.masked} />
          <h2>Mask map</h2>
          <p className="muted">On the server this map is sealed with your secret key and never leaves it.</p>
          <table>
            <thead>
              <tr>
                <th>Value</th>
                <th>Type</th>
                <th>Scope</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {[...rows.values()].map((d, i) => (
                <tr key={i}>
                  <td>
                    <code>{d.entity.value}</code>
                  </td>
                  <td>{kindName(d.entity.kind)}</td>
                  <td>{d.entity.scope}</td>
                  <td>{d.token ? <code>{d.token}</code> : d.action}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
