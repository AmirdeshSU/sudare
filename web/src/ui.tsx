import { useState } from "react";
import type { Provider, Stats } from "./api.ts";
import { defang, splitTokens } from "./text.ts";

/** Masked text with tokens highlighted. Text nodes only. */
export function Masked({ text }: { text: string }) {
  return (
    <>
      {splitTokens(text).map((p, i) =>
        p.token ? (
          <mark key={i} className="token">
            {p.text}
          </mark>
        ) : (
          <span key={i}>{p.text}</span>
        ),
      )}
    </>
  );
}

/** Plain model or log text, defanged. */
export const T = ({ children }: { children: string }) => <>{defang(children)}</>;

const MAX_ROWS = 2000;

/** Original vs masked, line by line. Masking keeps the line count, so rows align. */
export function Diff({ original, masked }: { original: string; masked: string }) {
  const [changedOnly, setChangedOnly] = useState(true);
  const a = original.replace(/\r\n?/g, "\n").split("\n");
  const b = masked.split("\n");
  const rows = b
    .map((m, i) => ({ n: i + 1, o: a[i] ?? "", m }))
    .filter((r) => !changedOnly || r.o !== r.m);
  return (
    <div>
      <label className="inline">
        <input type="checkbox" checked={changedOnly} onChange={(e) => setChangedOnly(e.target.checked)} /> Changed lines only
      </label>
      <div className="diff" role="table" aria-label="Original and masked lines">
        <div className="diff-head" role="row">
          <span role="columnheader">#</span>
          <span role="columnheader">Original (stays here)</span>
          <span role="columnheader">Masked (what is sent)</span>
        </div>
        {rows.slice(0, MAX_ROWS).map((r) => (
          <div key={r.n} className={r.o === r.m ? "diff-row" : "diff-row changed"} role="row">
            <span className="ln">{r.n}</span>
            <code>{r.o}</code>
            <code>
              <Masked text={r.m} />
            </code>
          </div>
        ))}
      </div>
      {rows.length > MAX_ROWS && (
        <p className="muted">
          Showing {MAX_ROWS} of {rows.length} rows. The full masked text is below.
        </p>
      )}
      {rows.length === 0 && <p className="muted">No line changed: nothing was masked.</p>}
    </div>
  );
}

export function StatChips({ stats }: { stats: Stats }) {
  const entries = Object.entries(stats.masked);
  return (
    <ul className="chips">
      {entries.map(([k, n]) => (
        <li key={k}>
          {k} <b>{stats.distinct[k] ?? 0}</b> <span className="muted">({n}×)</span>
        </li>
      ))}
      {entries.length === 0 && <li>nothing masked</li>}
      <li>
        kept <b>{stats.kept}</b>
      </li>
      {stats.dropped > 0 && (
        <li>
          dropped <b>{stats.dropped}</b>
        </li>
      )}
    </ul>
  );
}

export const Badge = ({ kind, children }: { kind: string; children: string }) => (
  <span className={`badge b-${kind.replace(/[^a-z_]/g, "")}`}>{children.replace(/_/g, " ")}</span>
);

export const ErrorBox = ({ error }: { error: string | null }) =>
  error ? (
    <p className="error" role="alert">
      {error}
    </p>
  ) : null;

/** Provider + model picker. Unready providers are listed, disabled, with the reason. */
export function ProviderPicker(props: {
  providers: Provider[];
  value: string;
  onChange: (name: string) => void;
  model: string;
  onModel: (m: string) => void;
}) {
  const current = props.providers.find((p) => p.name === props.value);
  return (
    <div className="row">
      <label>
        Provider
        <select value={props.value} onChange={(e) => props.onChange(e.target.value)}>
          {props.providers.map((p) => (
            <option key={p.name} value={p.name} disabled={!p.ready}>
              {p.name}
              {p.ready ? (p.local ? " (local)" : " (cloud)") : ` (unavailable: ${p.reason})`}
            </option>
          ))}
        </select>
      </label>
      <label>
        Model
        <input
          value={props.model}
          placeholder={current?.ready ? current.model : ""}
          onChange={(e) => props.onModel(e.target.value)}
        />
      </label>
    </div>
  );
}

/** The explicit go-ahead before anything goes to a non-local provider. */
export function CloudConfirm(props: { provider: Provider | undefined; checked: boolean; onChange: (v: boolean) => void; what: string }) {
  const p = props.provider;
  if (!p?.ready || p.local) return null;
  return (
    <label className="confirm">
      <input type="checkbox" checked={props.checked} onChange={(e) => props.onChange(e.target.checked)} />
      <span>
        I reviewed {props.what}. Send it to <b>{p.name}</b> at <code>{p.base_url}</code>.
      </span>
    </label>
  );
}

export const needsConfirm = (p: Provider | undefined) => Boolean(p?.ready && !p.local);
