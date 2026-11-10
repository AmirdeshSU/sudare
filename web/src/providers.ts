// LLM calls straight from the browser, for the standalone build. Same request shapes as
// crates/sudare-egress/src/llm.rs. Only masked messages from the wasm Session reach here.

export type Msg = { role: "system" | "user" | "assistant"; content: string };
export type Kind = "gemini" | "openai" | "anthropic" | "ollama";

type Spec = { label: string; base: string; model: string; local: boolean; context: number; keyHelp: string };

export const PROVIDERS: Record<Kind, Spec> = {
  gemini: {
    label: "Google Gemini",
    base: "https://generativelanguage.googleapis.com",
    model: "gemini-2.5-flash",
    local: false,
    context: 100_000,
    keyHelp: "https://aistudio.google.com/apikey",
  },
  openai: {
    label: "OpenAI",
    base: "https://api.openai.com/v1",
    model: "gpt-5-mini",
    local: false,
    context: 100_000,
    keyHelp: "https://platform.openai.com/api-keys",
  },
  anthropic: {
    label: "Anthropic",
    base: "https://api.anthropic.com",
    model: "claude-sonnet-5-5",
    local: false,
    context: 100_000,
    keyHelp: "https://console.anthropic.com/settings/keys",
  },
  // Needs OLLAMA_ORIGINS set to this site's origin (see README).
  ollama: { label: "Ollama on this computer", base: "http://127.0.0.1:11434", model: "qwen3:8b", local: true, context: 31_000, keyHelp: "" },
};

const turns = (m: Msg[]) => m.filter((x) => x.role !== "system");
const system = (m: Msg[]) => m.find((x) => x.role === "system")?.content ?? "";

export function request(kind: Kind, key: string, model: string, messages: Msg[], schema: unknown): [string, RequestInit] {
  const base = PROVIDERS[kind].base;
  const json = (headers: Record<string, string>, body: unknown): RequestInit => ({
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
    referrerPolicy: "no-referrer",
    credentials: "omit",
  });
  switch (kind) {
    case "gemini":
      return [
        `${base}/v1beta/models/${encodeURIComponent(model)}:generateContent`,
        // Key in a header, never in the URL.
        json(
          { "x-goog-api-key": key },
          {
            systemInstruction: { parts: [{ text: system(messages) }] },
            contents: turns(messages).map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] })),
            generationConfig: schema ? { temperature: 0, responseMimeType: "application/json" } : { temperature: 0 },
          },
        ),
      ];
    case "openai":
      return [
        `${base}/chat/completions`,
        json(
          { authorization: `Bearer ${key}` },
          {
            model,
            messages,
            ...(schema
              ? { response_format: { type: "json_schema", json_schema: { name: "incident_analysis", schema, strict: false } } }
              : {}),
          },
        ),
      ];
    case "anthropic":
      return [
        `${base}/v1/messages`,
        json(
          { "x-api-key": key, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
          { model, max_tokens: 8192, system: system(messages), messages: turns(messages) },
        ),
      ];
    case "ollama":
      return [
        `${base}/api/chat`,
        json({}, { model, stream: false, messages, options: { num_ctx: 16384, temperature: 0 }, ...(schema ? { format: schema } : {}) }),
      ];
  }
}

type Parts = { text?: string; type?: string }[];

export function text(kind: Kind, v: Record<string, unknown>): string | undefined {
  const join = (p: unknown) => (Array.isArray(p) ? (p as Parts).map((x) => x.text ?? "").join("") : undefined);
  const r = v as {
    message?: { content?: string };
    choices?: { message?: { content?: string } }[];
    content?: Parts;
    candidates?: { content?: { parts?: Parts } }[];
  };
  switch (kind) {
    case "ollama":
      return r.message?.content;
    case "openai":
      return r.choices?.[0]?.message?.content;
    case "anthropic":
      return join(r.content?.filter((p) => p.type === "text"));
    case "gemini":
      return join(r.candidates?.[0]?.content?.parts);
  }
}

/** One completion. Retries 429/503 twice (providers shed load under spikes). */
export async function complete(
  kind: Kind,
  key: string,
  model: string,
  messages: Msg[],
  schema?: unknown,
): Promise<{ text: string; model: string }> {
  const [url, init] = request(kind, key, model, messages, schema);
  for (let attempt = 1; ; attempt++) {
    let resp: Response;
    try {
      resp = await fetch(url, init);
    } catch {
      throw new Error(
        kind === "ollama"
          ? "Could not reach Ollama at 127.0.0.1:11434. Is it running, with OLLAMA_ORIGINS allowing this site?"
          : `Could not reach ${PROVIDERS[kind].label} (network error or blocked by the browser).`,
      );
    }
    if ((resp.status === 429 || resp.status === 503) && attempt < 3) {
      await new Promise((r) => setTimeout(r, 2000 * attempt));
      continue;
    }
    const body = await resp.text();
    if (!resp.ok) throw new Error(`${PROVIDERS[kind].label} returned HTTP ${resp.status}: ${body.replace(/\s+/g, " ").slice(0, 300)}`);
    let v: Record<string, unknown>;
    try {
      v = JSON.parse(body) as Record<string, unknown>;
    } catch {
      throw new Error(`${PROVIDERS[kind].label} returned something that isn't JSON`);
    }
    const t = text(kind, v);
    if (t === undefined) throw new Error(`Unexpected response shape from ${PROVIDERS[kind].label}`);
    return { text: t, model: typeof v.model === "string" ? v.model : model };
  }
}
