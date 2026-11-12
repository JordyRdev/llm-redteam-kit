/**
 * Self-contained HTML report (one file, no external assets) for GitHub Pages.
 * Every value from the target is escaped: the replies contain the very payloads under test.
 */
import type { CaseResult, RunResult, TargetResult } from "../runner.ts";

const esc = (s: unknown) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const clip = (s: string, n = 1500) => (s.length > n ? `${s.slice(0, n)}\n… (${s.length - n} more characters)` : s);

function ring(score: number): string {
  const r = 52;
  const c = 2 * Math.PI * r;
  const col = score >= 90 ? "#3fb950" : score >= 75 ? "#d29922" : score >= 50 ? "#f0883e" : "#f85149";
  return `<svg width="128" height="128" viewBox="0 0 128 128" class="ring"><circle cx="64" cy="64" r="${r}" stroke="#30363d" stroke-width="12" fill="none"/>
<circle cx="64" cy="64" r="${r}" stroke="${col}" stroke-width="12" fill="none" stroke-linecap="${score > 0 ? "round" : "butt"}" stroke-dasharray="${(c * score) / 100} ${c}" transform="rotate(-90 64 64)"/>
<text x="64" y="72" text-anchor="middle" font-size="30" font-weight="700" fill="#e6edf3">${score}</text></svg>`;
}

function caseRow(c: CaseResult): string {
  const icon = c.status === "pass" ? "✓" : c.status === "fail" ? "✘" : "–";
  const reason = c.checks.find((x) => x.status === "fail")?.detail ?? c.checks.find((x) => x.status === "skip" && c.status === "skip")?.detail ?? "";
  const transcript = c.transcript
    .map((t) => `<div class="turn ${t.role}"><span>${t.role === "user" ? "attacker" : "bot"}</span><pre>${esc(clip(t.content))}</pre></div>`)
    .join("");
  const checks = c.checks
    .map((x) => `<li class="${x.status}"><code>${esc(x.id)}</code> ${x.status}${x.detail ? `: ${esc(x.detail)}` : ""}</li>`)
    .join("");
  return `<details class="case ${c.status}"><summary><b class="ico">${icon}</b><code>${esc(c.id)}</code> ${esc(c.title)}<i>${esc(reason)}</i></summary>
<div class="body"><ul class="checks">${checks}</ul>${transcript}</div></details>`;
}

function target(t: TargetResult, r: RunResult): string {
  const gate = !t.gate
    ? `<span class="pill info">report only</span>`
    : t.gatePassed
      ? `<span class="pill ok">gate passed</span>`
      : `<span class="pill bad">gate failed</span>`;
  const risks = t.risks
    .map((k) => {
      const tested = k.pass + k.fail;
      const res =
        k.coverage === "process"
          ? `<span class="muted">manual: ${esc(k.manual ?? "")}</span>`
          : tested === 0
            ? `<span class="muted">not tested${k.skip ? ` (${k.skip} need setup)` : ""}</span>`
            : `<span class="bar"><span style="width:${(k.pass / tested) * 100}%"></span></span> ${k.pass}/${tested}${k.skip ? ` <span class="muted">+${k.skip} skipped</span>` : ""}`;
      return `<tr class="${k.fail ? "has-fail" : ""}"><td><code>${k.id}</code></td><td>${esc(k.name)}${k.coverage === "partial" ? ' <span class="muted">(partial)</span>' : ""}</td><td>${res}</td></tr>`;
    })
    .join("");
  const order = { fail: 0, pass: 1, skip: 2 } as const;
  const cases = [...t.cases].sort((a, b) => order[a.status] - order[b.status] || a.id.localeCompare(b.id)).map(caseRow).join("");
  return `<section class="target">
<header>${ring(t.score)}<div><h2>${esc(t.name)}</h2><p class="muted">${esc(t.host)}</p>
<p>${gate} <b class="ok">${t.pass} passed</b> · <b class="bad">${t.fail} failed</b> · <span class="muted">${t.skip} skipped</span></p>
${t.gate && !t.gatePassed ? `<ul class="reasons">${t.gateReasons.map((g) => `<li>${esc(g)}</li>`).join("")}</ul>` : ""}
<p class="muted">Gate: score ≥ ${r.minScore} and no failures in ${r.mustPass.map(esc).join(", ")}</p></div></header>
<table><thead><tr><th>OWASP 2026</th><th>Risk</th><th>Result</th></tr></thead><tbody>${risks}</tbody></table>
<h3>Attacks</h3>${cases}</section>`;
}

export function html(r: RunResult): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LLM red-team report</title>
<style>
:root{color-scheme:dark}body{margin:0;background:#0d1117;color:#e6edf3;font:15px/1.5 system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 20px}h1{margin:0 0 4px;font-size:26px}h2{margin:0;font-size:22px}h3{margin:28px 0 10px}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}.muted{color:#8b949e}
.target{background:#161b22;border:1px solid #30363d;border-radius:14px;padding:24px;margin:24px 0}
.target>header{display:flex;gap:24px;align-items:center;flex-wrap:wrap}.target header p{margin:6px 0}
.pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:13px;font-weight:600;margin-right:8px}
.pill.ok{background:#12351c;color:#3fb950}.pill.bad{background:#3d1419;color:#f85149}.pill.info{background:#1f2a3a;color:#79c0ff}
b.ok{color:#3fb950}b.bad{color:#f85149}.reasons{margin:4px 0;color:#f85149}
table{width:100%;border-collapse:collapse;margin-top:20px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d}th{color:#8b949e;font-weight:600;font-size:13px}
tr.has-fail td:first-child code{color:#f85149}
.bar{display:inline-block;width:120px;height:8px;background:#3d1419;border-radius:4px;vertical-align:middle;margin-right:8px;overflow:hidden}.bar span{display:block;height:100%;background:#3fb950}
.case{border:1px solid #21262d;border-radius:8px;margin:6px 0;background:#0d1117}.case summary{cursor:pointer;padding:8px 12px;list-style:none;display:flex;gap:10px;align-items:baseline}
.case summary i{color:#8b949e;font-style:normal;font-size:13px;margin-left:auto;max-width:55%;text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.case.fail .ico{color:#f85149}.case.pass .ico{color:#3fb950}.case.skip .ico{color:#8b949e}
.body{padding:4px 14px 14px}.checks{margin:6px 0 12px;padding-left:18px}.checks .fail{color:#f85149}.checks .pass{color:#3fb950}.checks .skip{color:#8b949e}
.turn{margin:8px 0}.turn span{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#8b949e}.turn.user span{color:#ffa657}
pre{white-space:pre-wrap;word-break:break-word;background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px;margin:4px 0;max-height:320px;overflow:auto}
footer{color:#8b949e;font-size:13px;margin-top:30px}a{color:#4493f8}
</style></head><body><main>
<h1>🛡️ LLM red-team report</h1>
<p class="muted">OWASP Top 10 for LLM Applications 2026 · ${esc(new Date(r.startedAt).toUTCString())}${r.judge ? ` · judge: ${esc(r.judge)}` : " · deterministic checks only"}</p>
${r.targets.map((t) => target(t, r)).join("")}
<footer>Generated by <a href="https://github.com/JordyRdev/llm-redteam-kit">llm-redteam-kit</a>. Canary and marker checks are deterministic: a failure is a proven leak or a followed instruction, not a model's opinion.</footer>
</main></body></html>`;
}
