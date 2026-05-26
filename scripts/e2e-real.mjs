// E2E sanity run: scan all real .github/workflows/*.yml files from the
// cloned archestra-ai/archestra repo and report aggregated findings.
//
//   node e2e-real.mjs
//
// Uses the local yaml@2.8.4 already installed under archestra/platform.

import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// Load yaml from archestra's pnpm-hoisted node_modules.
const YAML_PATH = "/Users/fabrimaran/Desktop/claudemain/autonomo/docs/ARTIFACTS/repos/archestra/platform/node_modules/.pnpm/yaml@2.8.4/node_modules/yaml/dist/index.js";
const { parse } = await import(YAML_PATH);

// Load runFreeRulesParsed via the same Function-shim trick the tests use.
const rulesSrc = readFileSync(join(here, "rules.js"), "utf8");
const stripped = rulesSrc
  .replace(/^import \{ parse \} from .*$/m, "let parse;")
  .replace(/^export function /gm, "function ");
const moduleExports = {};
new Function("exports", stripped + "\nexports.runFreeRulesParsed = runFreeRulesParsed;")(moduleExports);
const { runFreeRulesParsed } = moduleExports;

const WORKFLOWS_DIR = "/Users/fabrimaran/Desktop/claudemain/autonomo/docs/ARTIFACTS/repos/archestra/.github/workflows";
const files = readdirSync(WORKFLOWS_DIR).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"));

let totalFindings = 0;
const byId = {};
const perFile = [];

for (const file of files) {
  const text = readFileSync(join(WORKFLOWS_DIR, file), "utf8");
  let ast;
  try {
    ast = parse(text);
  } catch (e) {
    perFile.push({ file, findings: [{ id: "parse-error", severity: "high", title: e.message }] });
    continue;
  }
  const findings = runFreeRulesParsed(ast).filter((f) => f.id !== "empty");
  totalFindings += findings.length;
  for (const f of findings) byId[f.id] = (byId[f.id] ?? 0) + 1;
  perFile.push({ file, findings });
}

// Report
console.log(`Scanned ${files.length} workflows. ${totalFindings} total findings.\n`);
console.log("By rule id:");
for (const [id, n] of Object.entries(byId).sort((a, b) => b[1] - a[1])) {
  console.log(`  ${id.padEnd(28)} ${n}`);
}
console.log("\nPer file (first 3 findings each, truncated):");
for (const { file, findings } of perFile) {
  if (findings.length === 0) continue;
  console.log(`\n  ${file} — ${findings.length} findings`);
  for (const f of findings.slice(0, 3)) {
    console.log(`    [${f.severity.toUpperCase().padEnd(4)}] ${f.id} :: ${f.title}`);
    if (f.location) console.log(`           at ${f.location}`);
  }
  if (findings.length > 3) console.log(`    ... +${findings.length - 3} more`);
}
const clean = perFile.filter((p) => p.findings.length === 0).map((p) => p.file);
if (clean.length > 0) {
  console.log(`\nClean (no findings): ${clean.length} workflow(s)`);
  for (const f of clean) console.log(`  ${f}`);
}
