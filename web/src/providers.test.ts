import { test } from "node:test";
import assert from "node:assert/strict";
import { request, text, type Msg } from "./providers.ts";

const msgs: Msg[] = [
  { role: "system", content: "sys" },
  { role: "user", content: "[[USER_1]] logged in" },
];

test("keys go in headers, never URLs", () => {
  for (const kind of ["gemini", "openai", "anthropic"] as const) {
    const [url, init] = request(kind, "sk-secret-123", "m", msgs, { type: "object" });
    assert.ok(!url.includes("sk-secret-123"), kind);
    assert.ok(JSON.stringify(init.headers).includes("sk-secret-123"), kind);
    assert.equal(init.credentials, "omit");
  }
});

test("request shapes", () => {
  const gemini = JSON.parse(request("gemini", "k", "gemini-2.5-flash", msgs, {})[1].body as string);
  assert.equal(gemini.systemInstruction.parts[0].text, "sys");
  assert.deepEqual(gemini.contents, [{ role: "user", parts: [{ text: "[[USER_1]] logged in" }] }]);
  assert.equal(gemini.generationConfig.responseMimeType, "application/json");
  const anthropic = request("anthropic", "k", "m", msgs, undefined);
  assert.equal((anthropic[1].headers as Record<string, string>)["anthropic-dangerous-direct-browser-access"], "true");
  assert.equal(JSON.parse(anthropic[1].body as string).messages.length, 1);
  assert.ok(!("response_format" in JSON.parse(request("openai", "k", "m", msgs, undefined)[1].body as string)));
});

test("reply text", () => {
  assert.equal(text("gemini", { candidates: [{ content: { parts: [{ text: "a" }, { text: "b" }] } }] }), "ab");
  assert.equal(text("openai", { choices: [{ message: { content: "x" } }] }), "x");
  assert.equal(text("anthropic", { content: [{ type: "thinking" }, { type: "text", text: "y" }] }), "y");
  assert.equal(text("ollama", { message: { content: "z" } }), "z");
  assert.equal(text("gemini", {}), undefined);
});

test("vercel.json CSP allows exactly the providers' origins", async () => {
  const { readFile } = await import("node:fs/promises");
  const { PROVIDERS } = await import("./providers.ts");
  const cfg = JSON.parse(await readFile(new URL("../vercel.json", import.meta.url), "utf8"));
  const csp: string = cfg.headers[0].headers.find((h: { key: string }) => h.key === "Content-Security-Policy").value;
  const connect = csp.split(";").find((d) => d.trim().startsWith("connect-src"))!.trim().split(/\s+/).slice(1);
  const origins = Object.values(PROVIDERS).map((p) => new URL(p.base).origin);
  assert.deepEqual(new Set(connect), new Set(["'self'", ...origins]));
  assert.match(csp, /frame-ancestors 'none'/);
});
