#!/usr/bin/env node
// gha-shield CLI — scan .github/workflows/ for 13 categorized security rules.
// Usage:
//   npx Fabridev444/gha-shield [path] [--fail-on=high] [--format=text|json|github]

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { parse } from "yaml";

const SEVERITY_ORDER = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
const SEVERITY_LEVEL = { never: 99, crit: 0, high: 1, med: 2, low: 3, info: 4 };
const COLOR = { crit: "\x1b[31m", high: "\x1b[91m", med: "\x1b[33m", low: "\x1b[36m", info: "\x1b[90m", reset: "\x1b[0m", bold: "\x1b[1m" };

const args = process.argv.slice(2);
const flags = {};
const positional = [];
for (const a of args) {
  if (a.startsWith("--")) { const [k, v] = a.slice(2).split("="); flags[k] = v ?? true; }
  else positional.push(a);
}

if (flags.help || flags.h) {
  console.log(`gha-shield — scan GitHub Actions workflows for security issues

Usage:
  npx Fabridev444/gha-shield [path] [options]

Options:
  --fail-on=<severity>   Exit non-zero if any finding >= severity (crit|high|med|low|never). Default: high
  --format=<fmt>         Output format: text | json | github. Default: text (TTY) or github (CI)
  --help                 Show this help

Examples:
  npx Fabridev444/gha-shield                       # scan .github/workflows in cwd
  npx Fabridev444/gha-shield path/to/workflow.yml  # scan single file
  npx Fabridev444/gha-shield . --format=json       # JSON to stdout

Source: https://github.com/Fabridev444/gha-shield
Browser: https://fabridev444.github.io/gha-shield/
`);
  process.exit(0);
}

const target = positional[0] ?? ".github/workflows";
const failOn = (flags["fail-on"] || "high").toLowerCase();
const failLevel = SEVERITY_LEVEL[failOn] ?? 1;
const formatRaw = flags.format || (process.env.GITHUB_ACTIONS ? "github" : "text");
const format = formatRaw.toLowerCase();
const useColor = process.stdout.isTTY && format === "text";

const TRUSTED_ACTION_OWNERS = new Set(["actions", "github", "docker"]);
const SAFE_LEAF_FIELDS = new Set([
  "number", "id", "node_id", "comments",
  "created_at", "updated_at", "closed_at", "merged_at", "submitted_at",
  "locked", "draft", "merged", "rebaseable", "mergeable", "mergeable_state",
  "additions", "deletions", "changed_files", "commits", "review_comments",
  "state", "active_lock_reason",
]);

function eachStep(w, cb) {
  const jobs = w.jobs ?? {};
  for (const [jn, j] of Object.entries(jobs)) {
    if (!j || typeof j !== "object") continue;
    const steps = j.steps ?? [];
    for (let i = 0; i < steps.length; i++) cb(steps[i], { jobName: jn, stepIndex: i });
  }
}
function normalizeTriggers(on) {
  if (!on) return [];
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === "object") return Object.keys(on);
  return [];
}
function isTaintedRunExpr(text) {
  const EXPR = /\$\{\{\s*(github\.event\.(pull_request|issue|comment|head_commit|review|workflow_run)\.([\w.]+)|github\.head_ref|github\.ref|inputs\.([\w.]+))[^}]*\}\}/g;
  let m;
  while ((m = EXPR.exec(text)) !== null) {
    const p = m[3];
    if (p) { if (SAFE_LEAF_FIELDS.has(p.split(".").pop())) continue; return m[0]; }
    return m[0];
  }
  return null;
}

const RULES = [
  function r1(w) { const f = []; eachStep(w, (s, c) => { if (typeof s?.uses !== "string") return; const [ap, ref] = s.uses.split("@"); if (!ref || ap.startsWith("./") || ap.startsWith("docker://")) return; if (/^[a-f0-9]{40}$/i.test(ref)) return; f.push({ id: "unpinned-action", severity: "high", title: "Action not pinned to SHA", location: `jobs.${c.jobName}.steps[${c.stepIndex}].uses` }); }); return f; },
  function r2(w) { if (!normalizeTriggers(w.on).includes("pull_request_target")) return []; const f = []; eachStep(w, (s, c) => { if (typeof s?.uses !== "string" || !s.uses.startsWith("actions/checkout@")) return; const r = s.with?.ref; if (r != null && /(pull_request|head|sha|ref|pr)/i.test(String(r))) f.push({ id: "prtarget-checkout-prref", severity: "crit", title: "pull_request_target + PR-ref checkout", location: `jobs.${c.jobName}.steps[${c.stepIndex}].with.ref` }); }); return f; },
  function r3(w) { const f = []; eachStep(w, (s, c) => { if (typeof s?.run !== "string") return; const h = isTaintedRunExpr(s.run); if (h) f.push({ id: "cmd-injection", severity: "crit", title: "Untrusted GitHub context expanded into run:", location: `jobs.${c.jobName}.steps[${c.stepIndex}].run` }); }); return f; },
  function r4(w) { const ext = ["push","pull_request","pull_request_target","issues","issue_comment","release","schedule","workflow_run"]; if (!normalizeTriggers(w.on).some(t => ext.includes(t))) return []; if (w.permissions !== undefined) return []; const jobs = w.jobs ?? {}; const m = Object.keys(jobs).filter(n => jobs[n]?.permissions === undefined); if (!m.length) return []; return [{ id: "no-permissions", severity: "med", title: "No `permissions:` block", location: m.length === Object.keys(jobs).length ? "(workflow root)" : `jobs.{${m.join(",")}}` }]; },
  function r5(w) { const f = []; const S = /(auth|login|signin|verify|test|check|lint|audit|security|scan|coverage|typecheck|tsc)/i; eachStep(w, (s, c) => { if (s?.["continue-on-error"] !== true) return; if (!S.test(`${s?.name ?? ""} ${s?.run ?? ""} ${s?.uses ?? ""}`)) return; f.push({ id: "continue-on-error-auth", severity: "high", title: "continue-on-error on auth/test step", location: `jobs.${c.jobName}.steps[${c.stepIndex}]` }); }); return f; },
  function r6(w) { const f = []; const SEC = /\$\{\{\s*secrets\.[A-Z0-9_]+/i; const visit = (o, p) => { if (o && typeof o === "object" && typeof o.if === "string" && SEC.test(o.if)) f.push({ id: "secret-in-if", severity: "med", title: "Secret inside if:", location: p }); }; const jobs = w.jobs ?? {}; for (const [jn, j] of Object.entries(jobs)) { if (!j) continue; visit(j, `jobs.${jn}`); const ss = j.steps ?? []; for (let i = 0; i < ss.length; i++) visit(ss[i], `jobs.${jn}.steps[${i}]`); } return f; },
  function r7(w) { const f = []; const P = /\b(curl|wget|fetch)\s+[^|]*\|\s*(bash|sh|zsh|python3?|node|ruby|perl)\b/i; eachStep(w, (s, c) => { if (typeof s?.run === "string" && P.test(s.run)) f.push({ id: "curl-pipe-bash", severity: "high", title: "curl | bash style pipe", location: `jobs.${c.jobName}.steps[${c.stepIndex}].run` }); }); return f; },
  function r8(w) { const f = []; const DL = /(curl|wget)\s+[^|;]*?https?:\/\/(?:gist\.githubusercontent\.com|raw\.githubusercontent\.com|pastebin\.com|paste\.ee|0bin\.net|transfer\.sh)[^\s'"`]*/i; const CS = /(sha256sum|shasum|openssl\s+dgst|sha1sum|md5sum)/i; eachStep(w, (s, c) => { if (typeof s?.run !== "string") return; if (DL.test(s.run) && !CS.test(s.run)) f.push({ id: "untrusted-download", severity: "med", title: "Download w/o checksum", location: `jobs.${c.jobName}.steps[${c.stepIndex}].run` }); }); return f; },
  function r9(w) { if (!normalizeTriggers(w.on).includes("schedule")) return []; const tight = (p) => { if (p === undefined) return false; if (typeof p === "string") return p === "read-all" || p === "none"; if (typeof p === "object") return !Object.values(p).some((v) => /write/i.test(String(v))); return false; }; if (tight(w.permissions)) return []; const jobs = w.jobs ?? {}; const broad = Object.entries(jobs).filter(([_, j]) => !tight(j?.permissions)).map(([n]) => n); if (!broad.length) return []; return [{ id: "scheduled-broad-perms", severity: "med", title: "schedule: w/o tight permissions", location: broad.length === Object.keys(jobs).length ? "(workflow root)" : `jobs.{${broad.join(",")}}` }]; },
  function r10(w) { if (!normalizeTriggers(w.on).includes("workflow_run")) return []; const f = []; eachStep(w, (s, c) => { if (typeof s?.uses !== "string" || !s.uses.startsWith("actions/checkout@")) return; const r = s.with?.ref; if (r != null && /workflow_run|head_sha|pull_requests/i.test(String(r))) f.push({ id: "workflow-run-untrusted-checkout", severity: "crit", title: "workflow_run + untrusted ref checkout", location: `jobs.${c.jobName}.steps[${c.stepIndex}].with.ref` }); }); return f; },
  function r11(w) { const f = []; const KEY = /(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|jwt|bearer|sk[_-]live|sk[_-]test|rk[_-]live|rk[_-]test|pat[_-]|ghp[_-]|github[_-]?token|openai|anthropic|stripe)/i; const PREFIX = /^(sk-[A-Za-z0-9]{16,}|sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|rk_test_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|ghs_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|xox[abps]-[A-Za-z0-9-]{16,}|AIza[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})$/; const LONG = /^[A-Za-z0-9+/=_\-]{24,}$/; const SAFE = /^\s*\$\{\{\s*(secrets|vars|env|inputs|github|steps|matrix|needs|job|runner)\./; const insp = (o, p) => { const env = o?.env; if (!env || typeof env !== "object") return; for (const [k, raw] of Object.entries(env)) { if (raw == null) continue; const v = String(raw).trim(); if (!v || SAFE.test(v)) continue; if (PREFIX.test(v) || (KEY.test(k) && LONG.test(v))) f.push({ id: "hardcoded-secret", severity: "crit", title: `Hard-coded secret in env (${k})`, location: `${p}.env.${k}` }); } }; insp(w, "(workflow)"); const jobs = w.jobs ?? {}; for (const [jn, j] of Object.entries(jobs)) { if (!j) continue; insp(j, `jobs.${jn}`); const ss = j.steps ?? []; for (let i = 0; i < ss.length; i++) insp(ss[i], `jobs.${jn}.steps[${i}]`); } return f; },
  function r12(w) { const f = []; const TOK = /\$\{\{\s*(secrets\.GITHUB_TOKEN|github\.token)\s*\}\}/i; const SEC = /\$\{\{\s*secrets\.[A-Z0-9_]+/i; eachStep(w, (s, c) => { if (typeof s?.uses !== "string") return; const ap = s.uses.split("@")[0]; if (ap.startsWith("./") || ap.startsWith("docker://")) return; const owner = ap.split("/")[0]; if (TRUSTED_ACTION_OWNERS.has(owner)) return; const wb = s.with; if (!wb || typeof wb !== "object") return; for (const [k, raw] of Object.entries(wb)) { if (raw == null) continue; const v = String(raw); if (TOK.test(v)) f.push({ id: "third-party-action-token", severity: "high", title: `${ap} receives GITHUB_TOKEN`, location: `jobs.${c.jobName}.steps[${c.stepIndex}].with.${k}` }); else if (SEC.test(v)) f.push({ id: "third-party-action-token", severity: "med", title: `${ap} receives a secret`, location: `jobs.${c.jobName}.steps[${c.stepIndex}].with.${k}` }); } }); return f; },
  function r13(w) { const ext = ["push","pull_request","pull_request_target","issues","issue_comment","release","schedule","workflow_run"]; if (!normalizeTriggers(w.on).some(t => ext.includes(t))) return []; const jobs = w.jobs ?? {}; const m = Object.entries(jobs).filter(([_, j]) => j && typeof j === "object" && j["timeout-minutes"] === undefined && j.uses === undefined).map(([n]) => n); if (!m.length) return []; return [{ id: "no-timeout-minutes", severity: "low", title: "Job has no `timeout-minutes`", location: `jobs.{${m.join(",")}}` }]; },
];

function runRules(w) { return RULES.flatMap((r) => { try { return r(w) ?? []; } catch { return []; } }); }

function* walk(p) {
  for (const e of readdirSync(p, { withFileTypes: true })) {
    const fp = join(p, e.name);
    if (e.isDirectory()) yield* walk(fp);
    else if (e.isFile() && /\.ya?ml$/i.test(e.name)) yield fp;
  }
}

const tgtAbs = resolve(target);
if (!existsSync(tgtAbs)) { console.error(`gha-shield: path not found: ${tgtAbs}`); process.exit(2); }
const files = statSync(tgtAbs).isDirectory() ? [...walk(tgtAbs)] : [tgtAbs];
if (!files.length) { console.log(`gha-shield: no YAML files in ${tgtAbs}`); process.exit(0); }

const all = [];
const counts = { crit: 0, high: 0, med: 0, low: 0, info: 0 };
for (const f of files) {
  let ast;
  try { ast = parse(readFileSync(f, "utf8")); }
  catch (e) {
    if (format === "github") console.log(`::warning file=${f}::parse error: ${e.message}`);
    else console.error(`PARSE  ${f}: ${e.message}`);
    continue;
  }
  for (const fi of runRules(ast)) {
    all.push({ file: f, ...fi });
    counts[fi.severity]++;
    if (format === "github") {
      const lvl = fi.severity === "crit" || fi.severity === "high" ? "error" : (fi.severity === "med" ? "warning" : "notice");
      console.log(`::${lvl} file=${f}::[${fi.id}] ${fi.title} @ ${fi.location}`);
    }
  }
}

if (format === "json") {
  console.log(JSON.stringify({ files: files.length, counts, findings: all }, null, 2));
} else if (format === "text") {
  for (const fi of all) {
    const c = useColor ? COLOR[fi.severity] || "" : "";
    const r = useColor ? COLOR.reset : "";
    console.log(`${c}${fi.severity.toUpperCase().padEnd(4)}${r} ${fi.id.padEnd(35)} ${fi.file} ${fi.location}`);
  }
}

const summary = `gha-shield: ${files.length} workflow(s) scanned, ${all.length} finding(s) — ${counts.crit} crit · ${counts.high} high · ${counts.med} med · ${counts.low} low`;
console.log(useColor ? `\n${COLOR.bold}${summary}${COLOR.reset}` : `\n${summary}`);

const worst = all.reduce((acc, f) => Math.min(acc, SEVERITY_ORDER[f.severity] ?? 99), 99);
if (worst <= failLevel) {
  console.log(`gha-shield: exiting non-zero because findings include severity >= '${failOn}'`);
  process.exit(1);
}
