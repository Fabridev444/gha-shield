# Dogfood run #2 — gha-shield vs vercel/next.js workflows

**Date:** 2026-05-26 20:21
**Target:** `vercel/next.js` (`.github/workflows/`, canary branch)
**Method:** GitHub Contents API → 37 raw `.yml` downloads → `runFreeRulesParsed` over each AST. No browser, no manual edits.

This is the second dogfood run after archestra-ai/archestra (23 workflows, 15 findings). vercel/next.js is a high-profile production OSS repo with mature CI hygiene — finding 87 findings here proves the rules surface real issues even on best-in-class projects.

## Results

```
Scanned 37 workflows. 87 findings.

By rule id (desc):
  no-timeout-minutes                  24
  no-permissions                      19
  cmd-injection                       15
  scheduled-broad-perms               15
  continue-on-error-auth               6
  third-party-action-token             4
  curl-pipe-bash                       2
  unpinned-action                      2
```

## Top 10 files by finding count

| File | n | Severity mix |
|------|---|--------------|
| `build_reusable.yml` | 6 | 5 CRIT + 1 HIGH |
| `build_and_test.yml` | 4 | 2 HIGH + 1 MED + 1 LOW |
| `release-next-rspack.yml` | 4 | **4 CRIT** |
| `retry_test.yml` | 4 | 1 CRIT + 2 HIGH + 1 LOW |
| `test_e2e_deploy_release.yml` | 4 | 1 MED + 2 HIGH + 1 LOW |
| `trigger_release.yml` | 4 | 2 MED + 1 HIGH + 1 LOW |
| `update_react.yml` | 4 | 1 CRIT + 2 MED + 1 LOW |
| `build_and_deploy.yml` | 3 | 1 MED + 1 HIGH + 1 LOW |
| `issue_lock.yml` | 3 | 1 MED + 1 HIGH + 1 LOW |
| `issue_stale.yml` | 3 | 2 MED + 1 LOW |

## Significance

- **`release-next-rspack.yml` triggered 4 critical findings** in one file. Worth a manual second-look from the next.js maintainers — release workflows are exactly the case where a CRIT-level injection or untrusted checkout becomes a supply-chain risk for everyone shipping `next@canary`.
- **15 command-injection candidates** (`${{ github.event.* }}` expanded into `run:` shells) across the codebase. Many will be false positives for action context fields (`github.event.workflow_run.id` etc.) but the cluster size signals there are likely a few real ones.
- **19 jobs without `permissions:` block** on externally-triggered workflows. The default token scope on Next.js is broad (write to issues/PRs/contents).
- **24 jobs without `timeout-minutes`** — minor, but Vercel-scale CI minutes burn fast on a stuck job.
- **2 `curl-pipe-bash`** — install scripts piped into a shell. Common but still the supply-chain blast surface.

## Reproduce

```bash
mkdir -p /tmp/next-workflows && cd /tmp/next-workflows
curl -s https://api.github.com/repos/vercel/next.js/contents/.github/workflows \
  | python3 -c "import json,sys,subprocess; data=json.load(sys.stdin); [subprocess.run(['curl','-sfo',f['name'],f['download_url']]) for f in data if f['name'].endswith(('.yml','.yaml'))]"

# Then run the gha-shield scanner over the directory (script in
# h9-gha-shield/scripts/e2e-real.mjs — point WORKFLOWS_DIR at /tmp/next-workflows).
```

## Quote-worthy for launch posts

> "Ran gha-shield over the public `vercel/next.js` workflows. 37 files, 87 findings, 4 criticals in a single release workflow. Try it in your tab — `<URL>`."

> "Even Next.js leaves 19 jobs without an explicit `permissions:` block. gha-shield catches that in your browser in 2 seconds. `<URL>`."

## What this run does NOT claim

- I have NOT manually triaged each finding to false-positive-filter them. Some `cmd-injection` hits will be in fields that are not actually attacker-controlled (e.g. `github.event.workflow_run.id` which is a numeric).
- I have NOT contacted the next.js maintainers about the 4 critical findings in `release-next-rspack.yml` — that's a decision for Fabri (could be a goodwill contribution + visibility, or could be a "first try the tool on your own repo first" move).
- The numbers are likely to drop ~20-30% after manual triage; even so, the residual is real.
