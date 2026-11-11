import { describe, expect, it } from "vitest";
import { html } from "../src/report/html.ts";
import type { RunResult } from "../src/runner.ts";

describe("html report", () => {
  it("escapes payloads from the bot so the report itself is safe", () => {
    const payload = "<img src=x onerror=alert(1)><script>alert(2)</script>";
    const r: RunResult = {
      startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), marker: "RTK-X", judge: null,
      minScore: 80, mustPass: [],
      targets: [{
        name: payload, host: "h", gate: true, score: 0, pass: 0, fail: 1, skip: 0, gatePassed: false, gateReasons: [payload], risks: [],
        cases: [{ id: "X", title: payload, owasp: "LLM10", status: "fail", ms: 1,
          checks: [{ id: "c", status: "fail", detail: payload }],
          transcript: [{ role: "assistant", content: payload }] }],
      }],
    };
    const out = html(r);
    expect(out).not.toContain("<script>alert");
    expect(out).not.toContain("<img src=x");
    expect(out).toContain("&lt;script&gt;");
  });
});
