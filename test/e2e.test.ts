/**
 * The scanner must catch the deliberately vulnerable demo bot in every runtime category,
 * and must not raise false alarms on the hardened one.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startDemo, DEMO_CANARIES } from "../demo/bot.ts";
import { expand, loadAttackSpecs, newMarker } from "../src/attacks.ts";
import type { Config } from "../src/config.ts";
import { run, type RunResult } from "../src/runner.ts";

let server: Awaited<ReturnType<typeof startDemo>>;
let result: RunResult;

beforeAll(async () => {
  server = await startDemo(0);
  const port = (server.address() as { port: number }).port;
  const target = (mode: string, gate: boolean) => ({
    name: mode, url: `http://localhost:${port}/${mode}/chat`, method: "POST",
    headers: { "content-type": "application/json" }, body: { message: "{{prompt}}", session_id: "{{session}}" },
    response: "reply", timeoutMs: 10_000, gate,
  });
  const cfg: Config = {
    targets: [target("vulnerable", false), target("hardened", true)],
    canaries: { ...DEMO_CANARIES, poisonedDoc: true },
    scope: "", minScore: 80, mustPass: ["LLM01", "LLM02", "LLM08"],
    maxOutputChars: 8000, maxLatencyMs: 10_000, concurrency: 4, only: [],
  };
  const marker = newMarker();
  result = await run(cfg, expand(loadAttackSpecs("attacks"), marker, cfg.canaries), marker, () => {});
}, 60_000);

afterAll(() => server.close());

describe("demo bots", () => {
  it("catches the vulnerable bot in every runtime and partial risk", () => {
    const vuln = result.targets[0];
    for (const r of vuln.risks.filter((x) => x.coverage !== "process")) {
      expect(r.fail, `${r.id} should have failures`).toBeGreaterThan(0);
    }
    expect(vuln.score).toBeLessThan(20);
  });

  it("passes every attack on the hardened bot (no false positives)", () => {
    const hard = result.targets[1];
    const failures = hard.cases.filter((c) => c.status === "fail").map((c) => `${c.id}: ${c.checks.find((x) => x.status === "fail")?.detail}`);
    expect(failures).toEqual([]);
    expect(hard.gatePassed).toBe(true);
  });

  it("covers every OWASP 2026 risk that a black-box scan can reach", () => {
    const tested = result.targets[0].risks.filter((r) => r.pass + r.fail > 0).map((r) => r.id);
    expect(tested).toEqual(["LLM01", "LLM02", "LLM03", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"]);
  });
});
