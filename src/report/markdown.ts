/** Markdown summary for the GitHub job summary and PR comments. */
import type { RunResult } from "../runner.ts";

export function markdown(r: RunResult): string {
  const lines: string[] = ["## 🛡️ LLM red-team report", ""];
  for (const t of r.targets) {
    const gate = t.gate ? (t.gatePassed ? "✅ gate passed" : "❌ gate failed") : "ℹ️ report only";
    lines.push(`### ${t.name}: **${t.score}/100** · ${gate}`, "");
    lines.push(`${t.pass} passed · ${t.fail} failed · ${t.skip} skipped`, "");
    if (t.gate && !t.gatePassed) lines.push(...t.gateReasons.map((g) => `- ${g}`), "");
    lines.push("| OWASP 2026 | Risk | Result |", "|---|---|---|");
    for (const k of t.risks) {
      const res = k.coverage === "process" ? "manual check" : k.pass + k.fail === 0 ? "not tested" : `${k.fail ? "❌" : "✅"} ${k.pass}/${k.pass + k.fail}`;
      lines.push(`| ${k.id} | ${k.name} | ${res} |`);
    }
    const failed = t.cases.filter((c) => c.status === "fail");
    if (failed.length) {
      lines.push("", "<details><summary>Failed attacks</summary>", "");
      for (const c of failed) {
        const why = c.checks.filter((x) => x.status === "fail").map((x) => x.detail).join("; ");
        lines.push(`- **${c.id}** ${c.title}: ${why.replace(/\|/g, "\\|")}`);
      }
      lines.push("", "</details>");
    }
    lines.push("");
  }
  lines.push(`<sub>Run ${r.startedAt} · marker ${r.marker}${r.judge ? ` · judge ${r.judge}` : ""} · [llm-redteam-kit](https://github.com/JordyRdev/llm-redteam-kit)</sub>`);
  return lines.join("\n");
}
