import { runFreeRules } from "./rules.js";

const SEVERITY_ORDER = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
const SEVERITY_LABEL = { crit: "CRIT", high: "HIGH", med: "MED", low: "LOW", info: "INFO" };

const $yaml = document.getElementById("yaml-input");
const $key = document.getElementById("api-key");
const $scan = document.getElementById("scan-btn");
const $demo = document.getElementById("demo-btn");
const $upgrade = document.getElementById("upgrade-btn");
const $results = document.getElementById("results");
const $template = document.getElementById("finding-template");

const DEMO_WORKFLOW = `# Deliberately vulnerable demo — every rule fires.
name: ci
on:
  pull_request_target:
    types: [opened, synchronize]
  schedule:
    - cron: '0 0 * * *'

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      OPENAI_API_KEY: sk-aBcDeF0123456789AbCdEf0123456789AbCd
    steps:
      - uses: actions/checkout@v3
        with:
          ref: \${{ github.event.pull_request.head.sha }}

      - name: Install deps
        run: curl -fsSL https://example.com/install.sh | bash

      - name: Fetch helper
        run: wget https://gist.githubusercontent.com/foo/bar/raw/x.sh -O x.sh && bash x.sh

      - name: Build banner
        run: echo "Building PR titled \${{ github.event.pull_request.title }}"

      - name: Deploy
        uses: random-vendor/deploy-action@v1
        with:
          token: \${{ secrets.GITHUB_TOKEN }}

      - name: Audit
        if: \${{ secrets.AUDIT_KEY != '' }}
        run: npm audit --audit-level=critical
        continue-on-error: true
`;

$scan.addEventListener("click", onScan);
$demo.addEventListener("click", onDemo);
$upgrade.addEventListener("click", onUpgrade);
$yaml.addEventListener("keydown", (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === "Enter") onScan();
});

function onScan() {
  const text = $yaml.value;
  $scan.disabled = true;
  $scan.textContent = "Scanning…";
  // Defer to next tick so the disabled state actually paints.
  setTimeout(() => {
    try {
      const findings = runFreeRules(text);
      render(findings);
    } finally {
      $scan.disabled = false;
      $scan.textContent = "Scan";
    }
  }, 0);
}

function onDemo() {
  $yaml.value = DEMO_WORKFLOW;
  $yaml.scrollTop = 0;
  onScan();
}

function onUpgrade() {
  // V2 will trigger Stripe Checkout. For V1 the button is a clear future-state signal.
  alert(
    "Pro tier ($9 one-time) ships in V2 — Stripe + Cloudflare Worker.\n\n" +
      "What you get with Pro:\n" +
      "  • Bulk scan a whole .github/workflows/ folder\n" +
      "  • LLM-driven advanced patterns (BYOK): cross-job creds, eval/exec idioms, dev/prod confusion\n" +
      "  • Specific safer rewrites suggested per finding\n" +
      "  • Full PDF report export\n\n" +
      "Email the maintainer (in your receipt) to be notified at launch.",
  );
}

function render(findings) {
  // Sort by severity, stable within.
  const sorted = [...findings].sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 99;
    const sb = SEVERITY_ORDER[b.severity] ?? 99;
    return sa - sb;
  });

  // Reset panel.
  $results.innerHTML = "";
  const heading = document.createElement("h2");
  if (sorted.length === 0) {
    heading.textContent = "FINDINGS · 0";
    $results.append(heading);
    const empty = document.createElement("div");
    empty.className = "results-empty";
    empty.textContent = "No issues detected by the 6 free rules. Run Pro rules for LLM-driven analysis.";
    $results.append(empty);
    return;
  }
  const counts = sorted.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {});
  const summary = ["crit", "high", "med", "low", "info"]
    .filter((s) => counts[s])
    .map((s) => `${counts[s]} ${SEVERITY_LABEL[s]}`)
    .join(" · ");
  heading.textContent = `FINDINGS · ${sorted.length}${summary ? " · " + summary : ""}`;
  $results.append(heading);

  for (const f of sorted) {
    $results.append(renderFinding(f));
  }
}

function renderFinding(f) {
  const node = $template.content.firstElementChild.cloneNode(true);
  node.classList.add(f.severity);
  const sev = node.querySelector(".sev");
  sev.classList.add(f.severity);
  sev.textContent = SEVERITY_LABEL[f.severity] ?? f.severity.toUpperCase();
  node.querySelector(".finding-title").textContent = f.title;
  node.querySelector(".finding-desc").textContent = f.description;
  const loc = node.querySelector(".finding-loc");
  if (f.location) loc.textContent = f.location;
  else loc.remove();
  const fix = node.querySelector(".finding-fix");
  if (f.fix) fix.textContent = f.fix;
  else fix.remove();
  return node;
}
