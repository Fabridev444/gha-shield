// gha-shield — GitHub Action entrypoint.
// Pure Node 20 runtime, no node_modules. Reads workflow YAMLs from `path`,
// runs the 13 free-tier rules, writes GitHub annotations + a job summary,
// fails on the configured severity threshold.

const fs = require("node:fs");
const path = require("node:path");
const { parse: yamlParse } = require("yaml");

const SEVERITY_ORDER = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
const SEVERITY_LEVEL = { never: 99, crit: 0, high: 1, med: 2, low: 3, info: 4 };

function parseYaml(text) {
  try { return yamlParse(text); } catch (e) { throw e; }
}

function _unused_legacy_parser(text) {
  const lines = text.split(/\r?\n/);
  const root = {};
  const stack = [{ obj: root, indent: -1 }];

  function setValue(container, key, value) {
    if (Array.isArray(container)) container.push(value);
    else container[key] = value;
  }

  function parseScalar(s) {
    s = s.trim();
    if (!s.length) return "";
    // strip surrounding quotes
    if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
      return s.slice(1, -1);
    }
    if (s === "true") return true;
    if (s === "false") return false;
    if (s === "null" || s === "~") return null;
    if (/^-?\d+$/.test(s)) return parseInt(s, 10);
    if (/^-?\d+\.\d+$/.test(s)) return parseFloat(s);
    // flow sequence
    if (s.startsWith("[") && s.endsWith("]")) {
      return s.slice(1, -1).split(",").map((x) => parseScalar(x.trim())).filter((x) => x !== "");
    }
    return s;
  }

  for (let raw of lines) {
    // strip comments outside quotes (cheap: full-line `#` only, and trailing ` #`)
    let line = raw.replace(/^(\s*)#.*$/, "");
    if (!line.replace(/^\s+/, "").length) continue;
    const indent = line.match(/^( *)/)[1].length;
    line = line.slice(indent);

    // pop stack until parent indent < current indent
    while (stack.length > 1 && stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack[stack.length - 1].obj;

    // list item
    if (line.startsWith("- ")) {
      const rest = line.slice(2);
      if (!Array.isArray(parent[stack[stack.length - 1].lastKey])) {
        parent[stack[stack.length - 1].lastKey] = [];
      }
      const arr = parent[stack[stack.length - 1].lastKey];
      // inline mapping? `- uses: foo` -> object
      if (/^[A-Za-z_][A-Za-z0-9_-]*:/.test(rest)) {
        const item = {};
        arr.push(item);
        const colon = rest.indexOf(":");
        const k = rest.slice(0, colon).trim();
        const v = rest.slice(colon + 1).trim();
        if (v) item[k] = parseScalar(v);
        else item[k] = null;
        stack.push({ obj: item, indent, lastKey: k });
      } else {
        arr.push(parseScalar(rest));
      }
      continue;
    }
    if (line === "-") {
      if (!Array.isArray(parent[stack[stack.length - 1].lastKey])) {
        parent[stack[stack.length - 1].lastKey] = [];
      }
      const arr = parent[stack[stack.length - 1].lastKey];
      const item = {};
      arr.push(item);
      stack.push({ obj: item, indent, lastKey: null });
      continue;
    }

    // key: value
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim();
    const rest = line.slice(colon + 1);
    const value = rest.replace(/^\s+/, "");

    if (!value.length) {
      // multi-line / nested
      parent[key] = parent[key] ?? {};
      stack[stack.length - 1].lastKey = key;
      stack.push({ obj: parent[key], indent, lastKey: key });
    } else if (value.startsWith("|") || value.startsWith(">")) {
      // block scalar — collect following indented lines as raw string
      // For simplicity, we read no further; we mark as empty string here.
      // The rules that look at `run:` already handle a raw string OR multi-line.
      parent[key] = "";
      stack[stack.length - 1].lastKey = key;
      // Try to grab next lines greedily
      // (handled outside by another pass — skipping for simplicity)
    } else {
      setValue(parent, key, parseScalar(value));
      stack[stack.length - 1].lastKey = key;
    }
  }
  return root;
}

// ---------- Rules: trimmed copy of rules.js, no yaml import needed ----------
// Each rule is `(workflow) => Finding[]`.

const TRUSTED_ACTION_OWNERS = new Set(["actions", "github", "docker"]);

function eachStep(workflow, cb) {
  const jobs = workflow.jobs ?? {};
  for (const [jobName, job] of Object.entries(jobs)) {
    if (!job || typeof job !== "object") continue;
    const steps = job.steps ?? [];
    for (let i = 0; i < steps.length; i++) cb(steps[i], { jobName, stepIndex: i });
  }
}
function normalizeTriggers(on) {
  if (!on) return [];
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.map(String);
  if (typeof on === "object") return Object.keys(on);
  return [];
}

function r1(w) {
  const findings = [];
  eachStep(w, (step, ctx) => {
    if (typeof step?.uses !== "string") return;
    const [ap, ref] = step.uses.split("@");
    if (!ref) return;
    if (ap.startsWith("./") || ap.startsWith("docker://")) return;
    if (/^[a-f0-9]{40}$/i.test(ref)) return;
    findings.push({ id: "unpinned-action", severity: "high", title: "Action not pinned to SHA", location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].uses`, detail: step.uses });
  });
  return findings;
}
function r2(w) {
  if (!normalizeTriggers(w.on).includes("pull_request_target")) return [];
  const findings = [];
  eachStep(w, (step, ctx) => {
    if (typeof step?.uses !== "string" || !step.uses.startsWith("actions/checkout@")) return;
    const ref = step.with?.ref;
    if (ref != null && /(pull_request|head|sha|ref|pr)/i.test(String(ref))) {
      findings.push({ id: "prtarget-checkout-prref", severity: "crit", title: "pull_request_target + PR-ref checkout", location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].with.ref`, detail: String(ref) });
    }
  });
  return findings;
}
const TAINT = /\$\{\{\s*(?:github\.event\.(pull_request|issue|comment|head_commit|review|workflow_run)\.|github\.head_ref|github\.ref|inputs\.)/;
function r3(w) {
  const findings = [];
  eachStep(w, (step, ctx) => {
    if (typeof step?.run !== "string") return;
    const m = step.run.match(TAINT);
    if (m) findings.push({ id: "cmd-injection", severity: "crit", title: "Untrusted GitHub context expanded into run:", location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].run`, detail: m[0] });
  });
  return findings;
}
function r4(w) {
  const ext = ["push","pull_request","pull_request_target","issues","issue_comment","release","schedule","workflow_run"];
  if (!normalizeTriggers(w.on).some((t) => ext.includes(t))) return [];
  if (w.permissions !== undefined) return [];
  const jobs = w.jobs ?? {};
  const missing = Object.keys(jobs).filter((n) => jobs[n]?.permissions === undefined);
  if (!missing.length) return [];
  return [{ id: "no-permissions", severity: "med", title: "No `permissions:` block — broad GITHUB_TOKEN", location: missing.length === Object.keys(jobs).length ? "(workflow root)" : `jobs.{${missing.join(",")}}`, detail: missing.join(", ") }];
}
function r5(w) {
  const findings = [];
  const SUSPECT = /(auth|login|signin|verify|test|check|lint|audit|security|scan|coverage|typecheck|tsc)/i;
  eachStep(w, (step, ctx) => {
    if (step?.["continue-on-error"] !== true) return;
    const h = `${step?.name ?? ""} ${step?.run ?? ""} ${step?.uses ?? ""}`;
    if (!SUSPECT.test(h)) return;
    findings.push({ id: "continue-on-error-auth", severity: "high", title: "continue-on-error on auth/test step", location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}]`, detail: step.name ?? step.uses ?? "" });
  });
  return findings;
}
function r6(w) {
  const findings = [];
  const SECRET = /\$\{\{\s*secrets\.[A-Z0-9_]+/i;
  function visit(o, p) { if (o && typeof o === "object" && typeof o.if === "string" && SECRET.test(o.if)) findings.push({ id: "secret-in-if", severity: "med", title: "Secret inside if:", location: p, detail: o.if }); }
  const jobs = w.jobs ?? {};
  for (const [jn, job] of Object.entries(jobs)) { if (!job) continue; visit(job, `jobs.${jn}`); const steps = job.steps ?? []; for (let i = 0; i < steps.length; i++) visit(steps[i], `jobs.${jn}.steps[${i}]`); }
  return findings;
}
function r7(w) {
  const findings = [];
  const P = /\b(curl|wget|fetch)\s+[^|]*\|\s*(bash|sh|zsh|python3?|node|ruby|perl)\b/i;
  eachStep(w, (step, ctx) => {
    if (typeof step?.run !== "string") return;
    const m = step.run.match(P);
    if (m) findings.push({ id: "curl-pipe-bash", severity: "high", title: "curl | bash style pipe", location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].run`, detail: m[0] });
  });
  return findings;
}
function r8(w) {
  const findings = [];
  const DL = /(curl|wget)\s+[^|;]*?(https?:\/\/(?:gist\.githubusercontent\.com|raw\.githubusercontent\.com|pastebin\.com|paste\.ee|0bin\.net|transfer\.sh)[^\s'"`]*)/i;
  const CS = /(sha256sum|shasum|openssl\s+dgst|sha1sum|md5sum)/i;
  eachStep(w, (step, ctx) => {
    if (typeof step?.run !== "string") return;
    const m = step.run.match(DL);
    if (m && !CS.test(step.run)) findings.push({ id: "untrusted-download", severity: "med", title: "Download w/o checksum", location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].run`, detail: m[2] });
  });
  return findings;
}
function r9(w) {
  if (!normalizeTriggers(w.on).includes("schedule")) return [];
  const isTight = (p) => { if (p === undefined) return false; if (typeof p === "string") return p === "read-all" || p === "none"; if (typeof p === "object") return !Object.values(p).some((v) => /write/i.test(String(v))); return false; };
  if (isTight(w.permissions)) return [];
  const jobs = w.jobs ?? {};
  const broad = Object.entries(jobs).filter(([_, j]) => !isTight(j?.permissions)).map(([n]) => n);
  if (!broad.length) return [];
  return [{ id: "scheduled-broad-perms", severity: "med", title: "schedule: w/o tight permissions", location: broad.length === Object.keys(jobs).length ? "(workflow root)" : `jobs.{${broad.join(",")}}`, detail: broad.join(", ") }];
}
function r10(w) {
  if (!normalizeTriggers(w.on).includes("workflow_run")) return [];
  const findings = [];
  eachStep(w, (step, ctx) => {
    if (typeof step?.uses !== "string" || !step.uses.startsWith("actions/checkout@")) return;
    const ref = step.with?.ref;
    if (ref != null && /workflow_run|head_sha|pull_requests/i.test(String(ref))) findings.push({ id: "workflow-run-untrusted-checkout", severity: "crit", title: "workflow_run + untrusted ref checkout", location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].with.ref`, detail: String(ref) });
  });
  return findings;
}
function r11(w) {
  const findings = [];
  const KEY = /(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|jwt|bearer|sk[_-]live|sk[_-]test|rk[_-]live|rk[_-]test|pat[_-]|ghp[_-]|github[_-]?token|openai|anthropic|stripe)/i;
  const PREFIX = /^(sk-[A-Za-z0-9]{16,}|sk_live_[A-Za-z0-9]{16,}|sk_test_[A-Za-z0-9]{16,}|rk_live_[A-Za-z0-9]{16,}|rk_test_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{16,}|gho_[A-Za-z0-9]{16,}|ghs_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|xox[abps]-[A-Za-z0-9-]{16,}|AIza[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16})$/;
  const LONG = /^[A-Za-z0-9+/=_\-]{24,}$/;
  const SAFE = /^\s*\$\{\{\s*(secrets|vars|env|inputs|github|steps|matrix|needs|job|runner)\./;
  function inspect(o, p) {
    const env = o?.env;
    if (!env || typeof env !== "object") return;
    for (const [k, raw] of Object.entries(env)) {
      if (raw == null) continue;
      const v = String(raw).trim();
      if (!v || SAFE.test(v)) continue;
      if (PREFIX.test(v)) findings.push({ id: "hardcoded-secret", severity: "crit", title: `Hard-coded secret in env (${k})`, location: `${p}.env.${k}`, detail: "known prefix" });
      else if (KEY.test(k) && LONG.test(v)) findings.push({ id: "hardcoded-secret", severity: "crit", title: `Hard-coded secret in env (${k})`, location: `${p}.env.${k}`, detail: "long opaque + key name signal" });
    }
  }
  inspect(w, "(workflow)");
  const jobs = w.jobs ?? {};
  for (const [jn, job] of Object.entries(jobs)) { if (!job) continue; inspect(job, `jobs.${jn}`); const steps = job.steps ?? []; for (let i = 0; i < steps.length; i++) inspect(steps[i], `jobs.${jn}.steps[${i}]`); }
  return findings;
}
function r12(w) {
  const findings = [];
  const TOKEN = /\$\{\{\s*(secrets\.GITHUB_TOKEN|github\.token)\s*\}\}/i;
  const SECRET = /\$\{\{\s*secrets\.[A-Z0-9_]+/i;
  eachStep(w, (step, ctx) => {
    if (typeof step?.uses !== "string") return;
    const ap = step.uses.split("@")[0];
    if (ap.startsWith("./") || ap.startsWith("docker://")) return;
    const owner = ap.split("/")[0];
    if (TRUSTED_ACTION_OWNERS.has(owner)) return;
    const w_ = step.with;
    if (!w_ || typeof w_ !== "object") return;
    for (const [k, raw] of Object.entries(w_)) {
      if (raw == null) continue;
      const v = String(raw);
      if (TOKEN.test(v)) findings.push({ id: "third-party-action-token", severity: "high", title: `${ap} receives GITHUB_TOKEN`, location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].with.${k}`, detail: ap });
      else if (SECRET.test(v)) findings.push({ id: "third-party-action-token", severity: "med", title: `${ap} receives a secret`, location: `jobs.${ctx.jobName}.steps[${ctx.stepIndex}].with.${k}`, detail: ap });
    }
  });
  return findings;
}
function r13(w) {
  const ext = ["push","pull_request","pull_request_target","issues","issue_comment","release","schedule","workflow_run"];
  if (!normalizeTriggers(w.on).some((t) => ext.includes(t))) return [];
  const jobs = w.jobs ?? {};
  const missing = Object.entries(jobs).filter(([_, j]) => j && typeof j === "object" && j["timeout-minutes"] === undefined && j.uses === undefined).map(([n]) => n);
  if (!missing.length) return [];
  return [{ id: "no-timeout-minutes", severity: "low", title: "Job has no `timeout-minutes`", location: `jobs.{${missing.join(",")}}`, detail: missing.join(", ") }];
}

const RULES = [r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13];

function runRulesParsed(w) {
  return RULES.flatMap((r) => { try { return r(w) ?? []; } catch { return []; } });
}

// ---------- Main ----------

function* walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (e.isFile() && /\.ya?ml$/i.test(e.name)) yield p;
  }
}

function annotate(level, file, msg) {
  // GitHub workflow command format
  console.log(`::${level} file=${file}::${msg}`);
}

(function main() {
  const inputPath = process.env.INPUT_PATH || ".github/workflows";
  const failOn = (process.env["INPUT_FAIL-ON"] || "high").toLowerCase();
  const failLevel = SEVERITY_LEVEL[failOn] ?? 1;
  const format = (process.env.INPUT_FORMAT || "github").toLowerCase();

  if (!fs.existsSync(inputPath)) {
    console.log(`gha-shield: path not found: ${inputPath}`);
    process.exit(0);
  }
  const files = fs.statSync(inputPath).isDirectory() ? [...walk(inputPath)] : [inputPath];
  if (!files.length) { console.log("gha-shield: no YAML files found"); process.exit(0); }

  const all = [];
  let critC = 0, highC = 0, medC = 0, lowC = 0;
  for (const f of files) {
    let ast;
    try { ast = parseYaml(fs.readFileSync(f, "utf8")); }
    catch (e) { annotate("warning", f, `parse error: ${e.message}`); continue; }
    const findings = runRulesParsed(ast);
    for (const fi of findings) {
      all.push({ file: f, ...fi });
      if (fi.severity === "crit") critC++;
      else if (fi.severity === "high") highC++;
      else if (fi.severity === "med") medC++;
      else if (fi.severity === "low") lowC++;
      if (format === "github") {
        const level = fi.severity === "crit" || fi.severity === "high" ? "error" : (fi.severity === "med" ? "warning" : "notice");
        annotate(level, f, `[${fi.id}] ${fi.title} @ ${fi.location}`);
      }
    }
  }

  if (format === "json") console.log(JSON.stringify(all, null, 2));
  if (format === "text") {
    for (const fi of all) console.log(`${fi.severity.toUpperCase().padEnd(4)} ${fi.id.padEnd(35)} ${fi.file} ${fi.location}`);
  }

  console.log(`gha-shield: scanned ${files.length} workflow(s), ${all.length} finding(s) — ${critC} crit, ${highC} high, ${medC} med, ${lowC} low`);

  // Outputs
  const out = process.env.GITHUB_OUTPUT;
  if (out) {
    fs.appendFileSync(out, `findings_count=${all.length}\n`);
    fs.appendFileSync(out, `crit_count=${critC}\n`);
    fs.appendFileSync(out, `high_count=${highC}\n`);
  }

  // Summary
  const sum = process.env.GITHUB_STEP_SUMMARY;
  if (sum) {
    const lines = [
      "# gha-shield report",
      "",
      `Scanned **${files.length}** workflow(s). Total findings: **${all.length}** (crit ${critC} · high ${highC} · med ${medC} · low ${lowC})`,
      "",
      "| Severity | Rule | File | Location |",
      "| --- | --- | --- | --- |",
      ...all.map((f) => `| ${f.severity.toUpperCase()} | \`${f.id}\` | ${f.file} | \`${f.location}\` |`),
      "",
      "Open source: https://github.com/Fabridev444/gha-shield · Try in browser: https://fabridev444.github.io/gha-shield/",
    ];
    fs.appendFileSync(sum, lines.join("\n") + "\n");
  }

  // Decide exit
  const worst = all.reduce((acc, f) => Math.min(acc, SEVERITY_ORDER[f.severity] ?? 99), 99);
  if (worst <= failLevel) {
    console.log(`gha-shield: failing because findings include severity at or above '${failOn}'`);
    process.exit(1);
  }
})();
