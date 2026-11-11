/**
 * Runs every attack against every target and scores the results.
 * Leak checks run on every reply of a conversation; control checks on the last reply.
 */
import { randomUUID } from "node:crypto";
import type { Attack } from "./attacks.ts";
import { CONTROL_CHECKS, JUDGE_ONLY, leakChecks, type CheckContext, type CheckResult, type Status } from "./checks.ts";
import type { Config, TargetConfig } from "./config.ts";
import { judge, judgeable } from "./judge.ts";
import { OWASP_2026 } from "./owasp.ts";
import { send, type Turn } from "./target.ts";

export interface CaseResult {
  readonly id: string;
  readonly title: string;
  readonly owasp: string;
  readonly status: Status;
  readonly checks: readonly CheckResult[];
  readonly transcript: readonly Turn[];
  readonly ms: number;
}

export interface RiskSummary {
  readonly id: string;
  readonly name: string;
  readonly coverage: string;
  readonly manual?: string;
  readonly pass: number;
  readonly fail: number;
  readonly skip: number;
}

export interface TargetResult {
  readonly name: string;
  readonly host: string;
  readonly gate: boolean;
  readonly score: number;
  readonly pass: number;
  readonly fail: number;
  readonly skip: number;
  readonly gatePassed: boolean;
  readonly gateReasons: readonly string[];
  readonly risks: readonly RiskSummary[];
  readonly cases: readonly CaseResult[];
}

export interface RunResult {
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly marker: string;
  readonly judge: string | null;
  readonly minScore: number;
  readonly mustPass: readonly string[];
  readonly targets: readonly TargetResult[];
}

const statusOf = (checks: readonly CheckResult[]): Status =>
  checks.some((c) => c.status === "fail") ? "fail" : checks.some((c) => c.status === "pass") ? "pass" : "skip";

async function runAttack(cfg: Config, target: TargetConfig, attack: Attack, marker: string): Promise<CaseResult> {
  const base = { id: attack.id, title: attack.title, owasp: attack.owasp };
  if (attack.skipReason) {
    return { ...base, status: "skip", checks: [{ id: "requires", status: "skip", detail: attack.skipReason }], transcript: [], ms: 0 };
  }
  const session = `rtk-${randomUUID()}`;
  const history: Turn[] = [];
  const leaks = new Map<string, CheckResult>();
  let last: CheckContext | undefined;
  let total = 0;
  for (const prompt of attack.turns) {
    const reply = await send(target, prompt, session, history);
    total += reply.ms;
    history.push({ role: "user", content: prompt }, { role: "assistant", content: reply.text || `[${reply.error ?? "empty"}]` });
    last = {
      reply,
      sent: attack.turns.join("\n"),
      canaries: cfg.canaries,
      marker,
      maxOutputChars: cfg.maxOutputChars,
      maxLatencyMs: cfg.maxLatencyMs,
    };
    for (const r of leakChecks(last)) {
      const prev = leaks.get(r.id);
      if (!prev || r.status === "fail" || (prev.status === "skip" && r.status === "pass")) leaks.set(r.id, r);
    }
  }
  const ctx = last!;
  const controls: CheckResult[] = [];
  for (const id of attack.checks) {
    if (JUDGE_ONLY.has(id) && !cfg.judge) {
      controls.push({ id, status: "skip", detail: "needs a judge (see judge: in redteam.yml)" });
      continue;
    }
    const heuristic = CONTROL_CHECKS[id]?.(ctx) ?? { id, status: "skip" as Status, detail: "unknown check" };
    if (cfg.judge && judgeable(id) && ctx.reply.text) {
      const verdict = await judge(cfg.judge, id, attack.turns[attack.turns.length - 1], ctx.reply.text, cfg.scope);
      controls.push(verdict.status === "skip" ? heuristic : verdict);
    } else {
      controls.push(heuristic);
    }
  }
  const checks = [...leaks.values(), ...controls];
  return { ...base, status: statusOf(checks), checks, transcript: history, ms: total };
}

async function pool<T, R>(items: readonly T[], size: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(size, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    }),
  );
  return out;
}

export function summarise(cfg: Config, target: TargetConfig, cases: readonly CaseResult[]): TargetResult {
  const count = (s: Status, list = cases) => list.filter((c) => c.status === s).length;
  const pass = count("pass");
  const fail = count("fail");
  const score = pass + fail ? Math.round((pass / (pass + fail)) * 100) : 0;
  const risks = OWASP_2026.map((r) => {
    const mine = cases.filter((c) => c.owasp === r.id);
    return { id: r.id, name: r.name, coverage: r.coverage, manual: r.manual, pass: count("pass", mine), fail: count("fail", mine), skip: count("skip", mine) };
  });
  const gateReasons: string[] = [];
  if (score < cfg.minScore) gateReasons.push(`score ${score} is below the minimum of ${cfg.minScore}`);
  for (const id of cfg.mustPass) {
    const r = risks.find((x) => x.id === id);
    if (r && r.fail > 0) gateReasons.push(`${id} ${r.name} has ${r.fail} failing attack${r.fail > 1 ? "s" : ""}`);
  }
  let host = target.url;
  try {
    host = new URL(target.url).host;
  } catch {
    /* keep as is */
  }
  return { name: target.name, host, gate: target.gate, score, pass, fail, skip: count("skip"), gatePassed: gateReasons.length === 0, gateReasons, risks, cases };
}

export async function run(cfg: Config, attacks: readonly Attack[], marker: string, log = console.log): Promise<RunResult> {
  const startedAt = new Date().toISOString();
  const targets: TargetResult[] = [];
  for (const target of cfg.targets) {
    log(`\n▶ ${target.name} (${attacks.length} attacks)`);
    const cases = await pool(attacks, cfg.concurrency, async (a) => {
      const r = await runAttack(cfg, target, a, marker);
      const icon = r.status === "pass" ? "✓" : r.status === "fail" ? "✘" : "-";
      const why = r.status === "fail" ? `  ${r.checks.find((c) => c.status === "fail")?.detail ?? ""}` : "";
      log(`  ${icon} ${r.owasp} ${r.id.padEnd(16)} ${r.title}${why}`);
      return r;
    });
    targets.push(summarise(cfg, target, cases));
  }
  return {
    startedAt,
    finishedAt: new Date().toISOString(),
    marker,
    judge: cfg.judge ? cfg.judge.model : null,
    minScore: cfg.minScore,
    mustPass: cfg.mustPass,
    targets,
  };
}
