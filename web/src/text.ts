// Pure helpers, no imports, so `node --test` can run them directly.

/** Split masked text into plain runs and `[[TOKEN_N]]` runs. */
export function splitTokens(s: string): { text: string; token: boolean }[] {
  const out: { text: string; token: boolean }[] = [];
  const re = /\[\[[A-Z][A-Z0-9_]*_\d+\]\]/g;
  let last = 0;
  for (const m of s.matchAll(re)) {
    if (m.index > last) out.push({ text: s.slice(last, m.index), token: false });
    out.push({ text: m[0], token: true });
    last = m.index + m[0].length;
  }
  if (last < s.length) out.push({ text: s.slice(last), token: false });
  return out;
}

/** Defang links so a copied IOC can't be clicked or auto-linked by a chat tool. */
export function defang(s: string): string {
  return s.replace(/\bhttp(s?):\/\//gi, "hxxp$1://");
}

/** Read a cookie the server set for double-submit CSRF. */
export function cookie(all: string, name: string): string {
  for (const kv of all.split(";")) {
    const [k, ...v] = kv.trim().split("=");
    if (k === name) return v.join("=");
  }
  return "";
}

/** Route from location.hash: "#/a/abc" -> ["a", "abc"]. */
export function route(hash: string): string[] {
  return hash.replace(/^#\/?/, "").split("/").filter(Boolean);
}

/** Pull `token=...` out of a login fragment ("#token=abc"). */
export function fragmentToken(hash: string): string | null {
  const m = /^#token=([A-Za-z0-9_-]{16,})$/.exec(hash);
  return m ? m[1]! : null;
}
