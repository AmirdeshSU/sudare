import { cookie } from "./text.ts";

export type User = { id: number; username: string; role: "admin" | "user" };
export type Me = { user: User; mode: "single" | "multi"; connectors: string[] };
export type Provider =
  | { name: string; ready: true; local: boolean; model: string; base_url: string }
  | { name: string; ready: false; reason: string };
export type Stats = { masked: Record<string, number>; distinct: Record<string, number>; dropped: number; kept: number };
export type Preview = {
  preview_id: string;
  masked: string;
  digest: string;
  parser: string;
  lines: number;
  events: number;
  parse_errors: number;
  stats: Stats;
  public_indicators: number;
  kept_public_domains: string[];
  strict: boolean;
};
export type Summary = { id: string; created_at: number; verdict: string | null; severity: string | null; summary: string | null };
export type Enrichment = {
  provider: string;
  status: string;
  verdict: string | null;
  score: number | null;
  facts: string[];
  link: string | null;
  cached: boolean;
};
export type Analysis = {
  summary: string;
  verdict: string;
  severity: { level: string; rationale: string };
  confidence: { score: number; would_change_it: string };
  timeline: { timestamp: string | null; description: string; source_lines: number[] }[];
  entities: { ref: string; role: string; note: string }[];
  attack_techniques: { id: string; name: string; evidence: string; evidence_lines: number[] }[];
  recommended_actions: {
    containment: string[];
    investigation: { language: string; query: string; purpose: string }[];
    eradication: string[];
  };
  open_questions: string[];
};
export type Report = {
  schema_version: number;
  analysis: Analysis | null;
  raw_output: string | null;
  entities: { value: string; kind: string; scope: string; action: string; token: string | null; enrichment: Enrichment[] }[];
  warnings: { code: string; detail: string }[];
  meta: {
    provider: string;
    model: string;
    mode: string;
    parser: string;
    lines: number;
    events: number;
    parse_errors: number;
    mask: Stats;
    attack_version: string;
    created_at: string;
  };
};
export type ChatTurn = { question: string; answer: string };
export type Stored = { id: string; created_at: number; report: Report; masked_input: string; chat: ChatTurn[] };
export type Key = { name: string; kind: "llm" | "threat_intel"; saved: boolean; hint: string | null; updated_at: number | null };

export class ApiError extends Error {
  status: number;
  code: string;
  body: Record<string, unknown>;
  constructor(status: number, code: string, message: string, body: Record<string, unknown>) {
    super(message);
    this.status = status;
    this.code = code;
    this.body = body;
  }
}

/** Fired on any 401 so the app drops back to the login screen. */
export const LOGGED_OUT = "sudare:logged-out";

export async function api<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET") headers["x-csrf-token"] = cookie(document.cookie, "sudare_csrf");
  const r = await fetch(`/api${path}`, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = (await r.json().catch(() => ({}))) as Record<string, unknown>;
  if (!r.ok) {
    if (r.status === 401 && path !== "/login") window.dispatchEvent(new Event(LOGGED_OUT));
    throw new ApiError(r.status, String(data.error ?? "http"), String(data.message ?? r.statusText), data);
  }
  return data as T;
}

/** Navigate within the app (hash routes). */
export const go = (hash: string) => window.location.assign(hash);

export const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));
