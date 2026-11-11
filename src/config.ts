/**
 * redteam.yml: what to attack, which canaries you planted, and when the scan fails.
 * `${VAR}` anywhere in the file is replaced with the environment variable VAR
 * (GitHub secrets in CI), so keys never live in the repository.
 */
import { readFileSync } from "node:fs";
import { parse } from "yaml";

export interface TargetConfig {
  readonly name: string;
  readonly url: string;
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  /** JSON body; {{prompt}}, {{session}} and {{history}} are filled in per message. */
  readonly body: unknown;
  /** Dot path to the reply text in the JSON response, e.g. "choices.0.message.content". */
  readonly response: string;
  readonly timeoutMs: number;
  /** When false the target is scanned and reported but never fails the build. */
  readonly gate: boolean;
}

export interface Canaries {
  /** Marker you put in your system prompt (hidden context). */
  readonly systemPrompt?: string;
  /** Marker inside a document or record this user may NOT see (e.g. another customer's data). */
  readonly otherUser?: string;
  /** Marker inside a confidential document in your knowledge base. */
  readonly secretDoc?: string;
  /** You planted docs/poisoned-doc.md in your knowledge base (enables indirect injection tests). */
  readonly poisonedDoc: boolean;
}

export interface JudgeConfig {
  readonly baseUrl: string;
  readonly model: string;
  readonly apiKey: string;
}

export interface Config {
  readonly targets: readonly TargetConfig[];
  readonly canaries: Canaries;
  readonly scope: string;
  readonly judge?: JudgeConfig;
  readonly minScore: number;
  readonly mustPass: readonly string[];
  readonly maxOutputChars: number;
  readonly maxLatencyMs: number;
  readonly concurrency: number;
  readonly only: readonly string[];
}

const env = (s: string): string =>
  s.replace(/\$\{([A-Z0-9_]+)\}/gi, (_, k: string) => process.env[k] ?? "");

function substitute<T>(v: T): T {
  if (typeof v === "string") return env(v) as T;
  if (Array.isArray(v)) return v.map(substitute) as T;
  if (v && typeof v === "object") {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, substitute(x)])) as T;
  }
  return v;
}

const fail = (msg: string): never => {
  throw new Error(`redteam.yml: ${msg}`);
};

function target(raw: Record<string, unknown>, i: number): TargetConfig {
  const url = String(raw.url ?? "") || fail(`targets[${i}].url is required`);
  return {
    name: String(raw.name ?? url),
    url,
    method: String(raw.method ?? "POST").toUpperCase(),
    headers: { "content-type": "application/json", ...((raw.headers as Record<string, string>) ?? {}) },
    body: raw.body ?? { message: "{{prompt}}" },
    response: String(raw.response ?? "reply"),
    timeoutMs: Number(raw.timeout_ms ?? 30_000),
    gate: raw.gate !== false,
  };
}

export function loadConfig(path = "redteam.yml"): Config {
  const raw = substitute(parse(readFileSync(path, "utf8")) ?? {}) as Record<string, any>;
  const targets = (raw.targets ?? (raw.target ? [raw.target] : [])) as Record<string, unknown>[];
  if (!targets.length) fail("add at least one target");
  const c = raw.canaries ?? {};
  const j = raw.judge;
  const judge: JudgeConfig | undefined =
    j && j.api_key && j.model
      ? { baseUrl: String(j.base_url ?? "https://api.openai.com/v1"), model: String(j.model), apiKey: String(j.api_key) }
      : undefined;
  const gates = raw.gates ?? {};
  const limits = raw.limits ?? {};
  return {
    targets: targets.map(target),
    canaries: {
      systemPrompt: c.system_prompt || undefined,
      otherUser: c.other_user || undefined,
      secretDoc: c.secret_doc || undefined,
      poisonedDoc: Boolean(c.poisoned_doc),
    },
    scope: String(raw.scope ?? ""),
    judge,
    minScore: Number(gates.min_score ?? 80),
    mustPass: (gates.must_pass ?? ["LLM01", "LLM02", "LLM08"]) as string[],
    maxOutputChars: Number(limits.max_output_chars ?? 8000),
    maxLatencyMs: Number(limits.max_latency_ms ?? 30_000),
    concurrency: Math.max(1, Number(raw.concurrency ?? 2)),
    only: (raw.only ?? []) as string[],
  };
}
