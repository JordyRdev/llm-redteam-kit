/**
 * Talks to any chat endpoint over HTTP. The body is a JSON template from redteam.yml:
 *   {{prompt}}  the current message
 *   {{session}} a fresh id per attack, for apps that keep the conversation server-side
 *   {{history}} the earlier turns as [{role, content}] (OpenAI-style), for stateless apps
 */
import type { TargetConfig } from "./config.ts";

export interface Turn {
  readonly role: "user" | "assistant";
  readonly content: string;
}

export interface Reply {
  readonly text: string;
  readonly status: number;
  readonly ms: number;
  readonly error?: string;
}

function fill(template: unknown, vars: Record<string, unknown>): unknown {
  if (typeof template === "string") {
    const whole = /^\{\{(\w+)\}\}$/.exec(template);
    if (whole && whole[1] in vars) return vars[whole[1]];          // "{{history}}" -> the array itself
    return template.replace(/\{\{(\w+)\}\}/g, (m, k: string) => (k in vars ? String(vars[k]) : m));
  }
  if (Array.isArray(template)) {
    // [..., "{{history}}", ...] spreads the history into the array
    return template.flatMap((t) => (t === "{{history}}" ? (vars.history as unknown[]) : [fill(t, vars)]));
  }
  if (template && typeof template === "object") {
    return Object.fromEntries(Object.entries(template).map(([k, v]) => [k, fill(v, vars)]));
  }
  return template;
}

export function getPath(obj: unknown, path: string): unknown {
  return path.split(".").filter(Boolean).reduce<unknown>((o, key) => {
    if (o == null) return undefined;
    return Array.isArray(o) ? o[Number(key)] : (o as Record<string, unknown>)[key];
  }, obj);
}

export async function send(target: TargetConfig, prompt: string, session: string, history: Turn[]): Promise<Reply> {
  const body = fill(target.body, { prompt, session, history });
  const started = performance.now();
  try {
    const res = await fetch(target.url, {
      method: target.method,
      headers: target.headers,
      body: target.method === "GET" ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(target.timeoutMs),
    });
    const ms = Math.round(performance.now() - started);
    const raw = await res.text();
    let text = raw;
    try {
      const value = getPath(JSON.parse(raw), target.response);
      text = typeof value === "string" ? value : value == null ? "" : JSON.stringify(value);
    } catch {
      /* not JSON: use the raw body */
    }
    return { text, status: res.status, ms, error: res.ok ? undefined : `HTTP ${res.status}` };
  } catch (e) {
    return { text: "", status: 0, ms: Math.round(performance.now() - started), error: (e as Error).message };
  }
}
