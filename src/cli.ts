/**
 * llm-redteam-kit
 *
 *   npm run scan                      scan the targets in redteam.yml
 *   npm run scan -- --config my.yml   use another config
 *   npm run scan -- --only LLM01,HC-02  run a subset (OWASP ids or attack ids)
 *   npm run scan -- --no-gate         always exit 0 (report only)
 *
 * Writes report/index.html, report/results.json, report/summary.md and report/badge.svg.
 * Exits 1 when a gated target misses the score or a must-pass risk has a failure.
 */
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { expand, loadAttackSpecs, newMarker } from "./attacks.ts";
import { loadConfig } from "./config.ts";
import { badge } from "./report/badge.ts";
import { html } from "./report/html.ts";
import { markdown } from "./report/markdown.ts";
import { run } from "./runner.ts";

const args = process.argv.slice(2);
const opt = (name: string) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

async function main() {
  const cfg = loadConfig(opt("--config") ?? "redteam.yml");
  const only = opt("--only")?.split(",").map((s) => s.trim()).filter(Boolean) ?? [...cfg.only];
  const marker = newMarker();
  const attacks = expand(loadAttackSpecs(opt("--attacks") ?? "attacks"), marker, cfg.canaries, only);

  // The bundled demo bot starts in-process when a target points at it.
  let demo: { close: () => void } | undefined;
  if (cfg.targets.some((t) => /localhost:8787\/(vulnerable|hardened)/.test(t.url))) {
    const { startDemo } = await import("../demo/bot.ts");
    demo = await startDemo(8787).catch(() => undefined); // already running is fine
  }

  const configured = Object.entries(cfg.canaries).filter(([, v]) => v).map(([k]) => k);
  console.log(`llm-redteam-kit: ${attacks.length} attacks · canaries: ${configured.join(", ") || "none (leak checks skipped)"} · judge: ${cfg.judge?.model ?? "off"}`);

  const result = await run(cfg, attacks, marker);
  demo?.close();

  const out = opt("--out") ?? "report";
  mkdirSync(out, { recursive: true });
  writeFileSync(`${out}/results.json`, JSON.stringify(result, null, 2));
  writeFileSync(`${out}/index.html`, html(result));
  const md = markdown(result);
  writeFileSync(`${out}/summary.md`, md);
  const gated = result.targets.filter((t) => t.gate);
  writeFileSync(`${out}/badge.svg`, badge((gated[0] ?? result.targets[0])?.score ?? null));
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${md}\n`);

  console.log("");
  for (const t of result.targets) {
    const gate = t.gate ? (t.gatePassed ? "gate passed" : `gate FAILED: ${t.gateReasons.join("; ")}`) : "report only";
    console.log(`${t.name}: ${t.score}/100 (${t.pass} passed, ${t.fail} failed, ${t.skip} skipped) · ${gate}`);
  }
  console.log(`\nreport: ${out}/index.html`);
  if (!args.includes("--no-gate") && gated.some((t) => !t.gatePassed)) process.exit(1);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(2);
});
