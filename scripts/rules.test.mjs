// Pure-logic tests for the 6 free-tier rules.
// Run from this directory with:
//   node --test rules.test.mjs
//
// Tests bypass the YAML parser by feeding hand-crafted ASTs directly to
// `runFreeRulesParsed`. The `rules.js` module is imported via a tiny shim that
// strips out the runtime `import { parse } from "https://esm.sh/yaml@2"` line —
// node refuses to follow HTTPS imports without --experimental-network-imports,
// but the YAML parse step is unreachable from runFreeRulesParsed anyway.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const rulesSrc = readFileSync(join(here, "rules.js"), "utf8");
// Strip ESM-only bits so we can eval in a plain Function scope.
const stripped = rulesSrc
  .replace(/^import \{ parse \} from .*$/m, "let parse;")
  .replace(/^export function /gm, "function ");
// Eval the module in an isolated namespace via Function constructor.
const moduleExports = {};
const moduleFactory = new Function(
  "exports",
  stripped +
    "\nexports.runFreeRulesParsed = runFreeRulesParsed;" +
    "\nexports.runFreeRules = runFreeRules;",
);
moduleFactory(moduleExports);
const { runFreeRulesParsed } = moduleExports;

function hasFinding(findings, id) {
  return findings.some((f) => f.id === id);
}

function countFinding(findings, id) {
  return findings.filter((f) => f.id === id).length;
}

// ---------- Rule 1: unpinned actions ----------

test("rule1 — flags tag-pinned actions", () => {
  const w = {
    jobs: {
      build: { steps: [{ uses: "actions/checkout@v3" }] },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.ok(hasFinding(f, "unpinned-action"), "should flag tag pin");
});

test("rule1 — passes SHA-pinned actions", () => {
  const w = {
    jobs: {
      build: {
        steps: [{ uses: "actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" }],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "unpinned-action"), 0);
});

test("rule1 — skips local actions (./action)", () => {
  const w = {
    jobs: { build: { steps: [{ uses: "./my-local-action" }] } },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "unpinned-action"), 0);
});

test("rule1 — flags multiple unpinned across jobs", () => {
  const w = {
    jobs: {
      build: { steps: [{ uses: "actions/checkout@v3" }] },
      deploy: { steps: [{ uses: "actions/setup-node@v4" }] },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "unpinned-action"), 2);
});

// ---------- Rule 2: pull_request_target + PR checkout ----------

test("rule2 — flags pull_request_target with PR ref checkout", () => {
  const w = {
    on: { pull_request_target: { types: ["opened"] } },
    jobs: {
      build: {
        steps: [
          {
            uses: "actions/checkout@v3",
            with: { ref: "${{ github.event.pull_request.head.sha }}" },
          },
        ],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.ok(hasFinding(f, "prtarget-checkout-prref"), "should flag privilege escalation");
});

test("rule2 — does NOT flag pull_request_target with no PR ref", () => {
  const w = {
    on: ["pull_request_target"],
    jobs: { build: { steps: [{ uses: "actions/checkout@v3" }] } },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "prtarget-checkout-prref"), 0);
});

test("rule2 — does NOT flag plain pull_request trigger", () => {
  const w = {
    on: ["pull_request"],
    jobs: {
      build: {
        steps: [
          { uses: "actions/checkout@v3", with: { ref: "${{ github.event.pull_request.head.sha }}" } },
        ],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "prtarget-checkout-prref"), 0);
});

// ---------- Rule 3: command injection ----------

test("rule3 — flags PR title interpolated in run", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          { run: 'echo "Title is ${{ github.event.pull_request.title }}"' },
        ],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.ok(hasFinding(f, "cmd-injection"));
});

test("rule3 — flags head_ref in run", () => {
  const w = {
    jobs: {
      build: { steps: [{ run: "git fetch origin ${{ github.head_ref }}" }] },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.ok(hasFinding(f, "cmd-injection"));
});

test("rule3 — passes safe env-mediated reference", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          {
            env: { PR_TITLE: "${{ github.event.pull_request.title }}" },
            run: 'echo "$PR_TITLE"',
          },
        ],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "cmd-injection"), 0);
});

// ---------- Rule 4: missing permissions ----------

test("rule4 — flags missing permissions on pull_request workflow", () => {
  const w = {
    on: ["pull_request"],
    jobs: { build: { steps: [{ uses: "actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" }] } },
  };
  const f = runFreeRulesParsed(w);
  assert.ok(hasFinding(f, "no-permissions"));
});

test("rule4 — passes when workflow has top-level permissions", () => {
  const w = {
    on: ["push"],
    permissions: "read-all",
    jobs: { build: { steps: [{ uses: "actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" }] } },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "no-permissions"), 0);
});

test("rule4 — passes for workflow_dispatch only (no external trigger)", () => {
  const w = {
    on: ["workflow_dispatch"],
    jobs: { build: { steps: [{ run: "echo hi" }] } },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "no-permissions"), 0);
});

// ---------- Rule 5: continue-on-error on auth/test ----------

test("rule5 — flags continue-on-error on a step named 'Run tests'", () => {
  const w = {
    jobs: {
      build: {
        steps: [{ name: "Run tests", run: "npm test", "continue-on-error": true }],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.ok(hasFinding(f, "continue-on-error-auth"));
});

test("rule5 — flags continue-on-error on an audit step", () => {
  const w = {
    jobs: {
      build: {
        steps: [{ name: "npm audit", run: "npm audit --production", "continue-on-error": true }],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.ok(hasFinding(f, "continue-on-error-auth"));
});

test("rule5 — does NOT flag continue-on-error on a benign upload", () => {
  const w = {
    jobs: {
      build: {
        steps: [{ name: "Upload artifact", uses: "actions/upload-artifact@v4", "continue-on-error": true }],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "continue-on-error-auth"), 0);
});

// ---------- Rule 6: secrets in if: ----------

test("rule6 — flags secret reference inside if:", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          {
            if: "${{ secrets.MY_KEY != '' }}",
            run: "echo deploying",
          },
        ],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.ok(hasFinding(f, "secret-in-if"));
});

test("rule6 — passes env-mediated guard", () => {
  const w = {
    jobs: {
      build: {
        env: { HAS_KEY: "${{ secrets.MY_KEY != '' }}" },
        steps: [{ if: "env.HAS_KEY == 'true'", run: "echo deploying" }],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  assert.equal(countFinding(f, "secret-in-if"), 0);
});

// ---------- Rule 7: curl | bash ----------

test("rule7 — flags `curl | bash` in run", () => {
  const w = {
    jobs: { build: { steps: [{ run: "curl -fsSL https://example.com/install.sh | bash" }] } },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "curl-pipe-bash"));
});

test("rule7 — flags `wget -O- ... | sh`", () => {
  const w = {
    jobs: { build: { steps: [{ run: "wget -qO- https://example.com/install.sh | sh" }] } },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "curl-pipe-bash"));
});

test("rule7 — passes safe download-then-verify pattern", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          {
            run: "curl -fsSLO https://example.com/install.sh && echo 'aaa  install.sh' | sha256sum -c && bash install.sh",
          },
        ],
      },
    },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "curl-pipe-bash"), 0);
});

// ---------- Rule 8: untrusted download without checksum ----------

test("rule8 — flags gist download without checksum", () => {
  const w = {
    jobs: { build: { steps: [{ run: "curl -fsSL https://gist.githubusercontent.com/foo/bar/raw/x -o x.sh" }] } },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "untrusted-download"));
});

test("rule8 — flags pastebin download", () => {
  const w = {
    jobs: { build: { steps: [{ run: "wget https://pastebin.com/raw/abc123 -O p.sh" }] } },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "untrusted-download"));
});

test("rule8 — passes when checksum verification is present", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          {
            run: "curl https://raw.githubusercontent.com/foo/bar/abc/script.sh -o s.sh && sha256sum -c sums.txt",
          },
        ],
      },
    },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "untrusted-download"), 0);
});

// ---------- Rule 9: scheduled workflow with broad/missing permissions ----------

test("rule9 — flags schedule trigger without permissions", () => {
  const w = {
    on: { schedule: [{ cron: "0 0 * * *" }] },
    jobs: { build: { steps: [{ run: "echo nightly" }] } },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "scheduled-broad-perms"));
});

test("rule9 — flags schedule with write permission in object", () => {
  const w = {
    on: ["schedule"],
    permissions: { contents: "write" },
    jobs: { build: { steps: [{ run: "echo nightly" }] } },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "scheduled-broad-perms"));
});

test("rule9 — passes schedule + permissions read-all", () => {
  const w = {
    on: ["schedule"],
    permissions: "read-all",
    jobs: { build: { steps: [{ run: "echo nightly" }] } },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "scheduled-broad-perms"), 0);
});

// ---------- Rule 10: workflow_run untrusted checkout ----------

test("rule10 — flags workflow_run + checkout of head_sha", () => {
  const w = {
    on: ["workflow_run"],
    jobs: {
      build: {
        steps: [
          {
            uses: "actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            with: { ref: "${{ github.event.workflow_run.head_sha }}" },
          },
        ],
      },
    },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "workflow-run-untrusted-checkout"));
});

test("rule10 — passes workflow_run with no ref (base checkout)", () => {
  const w = {
    on: ["workflow_run"],
    jobs: { build: { steps: [{ uses: "actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" }] } },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "workflow-run-untrusted-checkout"), 0);
});

// ---------- Rule 11: hardcoded credentials in env ----------

test("rule11 — flags hardcoded OpenAI sk- key", () => {
  const w = {
    jobs: {
      build: {
        env: { OPENAI_API_KEY: "sk-abcdef0123456789abcdef0123456789" },
        steps: [{ run: "node test.js" }],
      },
    },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "hardcoded-secret"));
});

test("rule11 — flags hardcoded Stripe sk_live_ key", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          {
            env: { STRIPE_KEY: "sk_live_abcdef0123456789abcdef" },
            run: "stripe webhook",
          },
        ],
      },
    },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "hardcoded-secret"));
});

test("rule11 — flags long opaque value under SECRET-named key", () => {
  const w = {
    env: { MY_SECRET: "Zk9pQrStUvWxYz0123456789abcd" },
    jobs: { build: { steps: [{ run: "echo $MY_SECRET" }] } },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "hardcoded-secret"));
});

test("rule11 — passes secrets.* reference (safe)", () => {
  const w = {
    jobs: {
      build: {
        env: { OPENAI_API_KEY: "${{ secrets.OPENAI_API_KEY }}" },
        steps: [{ run: "node test.js" }],
      },
    },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "hardcoded-secret"), 0);
});

test("rule11 — passes env.* and vars.* references", () => {
  const w = {
    jobs: {
      build: {
        env: {
          TOKEN: "${{ env.GITHUB_TOKEN }}",
          KEY: "${{ vars.SHARED_KEY }}",
        },
        steps: [{ run: "echo hi" }],
      },
    },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "hardcoded-secret"), 0);
});

test("rule11 — does NOT flag short or benign env values", () => {
  const w = {
    jobs: {
      build: {
        env: { NODE_ENV: "production", FOO: "bar", URL: "https://example.com" },
        steps: [{ run: "echo hi" }],
      },
    },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "hardcoded-secret"), 0);
});

// ---------- Rule 12: third-party action receiving a token/secret ----------

test("rule12 — flags untrusted action receiving GITHUB_TOKEN (HIGH)", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          {
            uses: "some-org/deploy-action@v1",
            with: { token: "${{ secrets.GITHUB_TOKEN }}" },
          },
        ],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  const fi = f.filter((x) => x.id === "third-party-action-token");
  assert.equal(fi.length, 1);
  assert.equal(fi[0].severity, "high");
});

test("rule12 — flags untrusted action receiving a custom secret (MED)", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          {
            uses: "some-org/notify@v1",
            with: { slack_webhook: "${{ secrets.SLACK_WEBHOOK_URL }}" },
          },
        ],
      },
    },
  };
  const f = runFreeRulesParsed(w);
  const fi = f.filter((x) => x.id === "third-party-action-token");
  assert.equal(fi.length, 1);
  assert.equal(fi[0].severity, "med");
});

test("rule12 — passes trusted owner (actions/github-script)", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          {
            uses: "actions/github-script@v7",
            with: { "github-token": "${{ secrets.GITHUB_TOKEN }}" },
          },
        ],
      },
    },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "third-party-action-token"), 0);
});

test("rule12 — passes local action (./.github/actions/foo)", () => {
  const w = {
    jobs: {
      build: {
        steps: [
          { uses: "./.github/actions/foo", with: { token: "${{ secrets.GITHUB_TOKEN }}" } },
        ],
      },
    },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "third-party-action-token"), 0);
});

test("rule12 — passes action receiving no credentials", () => {
  const w = {
    jobs: {
      build: {
        steps: [{ uses: "some-org/cache@v1", with: { path: "node_modules" } }],
      },
    },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "third-party-action-token"), 0);
});

// ---------- Rule 13: no timeout-minutes ----------

test("rule13 — flags missing timeout-minutes on push workflow", () => {
  const w = {
    on: ["push"],
    jobs: { build: { steps: [{ run: "echo hi" }] } },
  };
  assert.ok(hasFinding(runFreeRulesParsed(w), "no-timeout-minutes"));
});

test("rule13 — passes when timeout-minutes set", () => {
  const w = {
    on: ["push"],
    jobs: { build: { "timeout-minutes": 10, steps: [{ run: "echo hi" }] } },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "no-timeout-minutes"), 0);
});

test("rule13 — passes for workflow_dispatch-only (manual)", () => {
  const w = {
    on: ["workflow_dispatch"],
    jobs: { build: { steps: [{ run: "echo manual" }] } },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "no-timeout-minutes"), 0);
});

test("rule13 — skips reusable workflow caller (job.uses)", () => {
  const w = {
    on: ["push"],
    jobs: { call: { uses: "owner/repo/.github/workflows/wf.yml@v1" } },
  };
  assert.equal(countFinding(runFreeRulesParsed(w), "no-timeout-minutes"), 0);
});

// ---------- Smoke: clean workflow returns 0 findings (other than empty/parse) ----------

test("clean SHA-pinned workflow with permissions returns 0 actionable findings", () => {
  const w = {
    on: ["push"],
    permissions: "read-all",
    jobs: {
      build: {
        steps: [
          { uses: "actions/checkout@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0" },
          { name: "Run tests", run: "npm test" },
        ],
        "timeout-minutes": 10,
      },
    },
  };
  const f = runFreeRulesParsed(w);
  for (const id of [
    "unpinned-action", "prtarget-checkout-prref", "cmd-injection",
    "no-permissions", "continue-on-error-auth", "secret-in-if",
    "curl-pipe-bash", "untrusted-download", "scheduled-broad-perms",
    "workflow-run-untrusted-checkout", "hardcoded-secret",
    "third-party-action-token", "no-timeout-minutes",
  ]) {
    assert.equal(countFinding(f, id), 0, `${id} should not fire on clean workflow`);
  }
});
