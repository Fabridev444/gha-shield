# gha-shield real-world audits

These are unedited scan results from running `gha-shield` over the public `.github/workflows/` of large OSS projects. No claims about exploitability — these are the categorized findings the 13 free rules raise. Every line is reproducible: clone the target repo, run `npx Fabridev444/gha-shield` or open `https://fabridev444.github.io/gha-shield/` and paste the workflow.

---

## `vercel/next.js` — 37 workflows, 87 findings

Scanned: 2026-05-26, `canary` branch.

```
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

Top 5 workflows by finding count:

| File | n | Severity mix |
|------|---|--------------|
| `release-next-rspack.yml` | 4 | **4 CRIT** |
| `build_reusable.yml` | 6 | 5 CRIT + 1 HIGH |
| `build_and_test.yml` | 4 | 2 HIGH + 1 MED + 1 LOW |
| `retry_test.yml` | 4 | 1 CRIT + 2 HIGH + 1 LOW |
| `update_react.yml` | 4 | 1 CRIT + 2 MED + 1 LOW |

The 4 critical findings in `release-next-rspack.yml` are concentrated in one release workflow. Worth a manual triage from the Next.js maintainers — release pipelines are exactly the case where a CRIT-level finding can become a supply-chain risk for everyone shipping `next@canary`. I am not opening an upstream issue or PR; this is the maintainers' call.

The 15 `cmd-injection` candidates are expressions like `${{ github.event.* }}` interpolated into `run:` blocks. Many will be false positives for fields that are not in practice attacker-controlled (numeric IDs, internal refs). Manual triage will likely cut the cluster ~30%. Even so, residuals remain real.

The 19 `no-permissions` findings are jobs on external triggers without an explicit `permissions:` block — they inherit the org default token scope. Tightening to `read-all` at the workflow root and per-job overrides closes the surface.

---

## `archestra-ai/archestra` — 23 workflows, 15 findings

Scanned: 2026-05-26, `main` branch.

```
By rule id:
  continue-on-error-auth      2
  no-timeout-minutes         13
```

Findings concentrated in two test workflows:

```
platform-e2e-tests.yml
  HIGH continue-on-error-auth jobs.platform-e2e-tests.steps[6]
  HIGH continue-on-error-auth jobs.platform-readonly-vault-e2e-tests.steps[5]
```

Both are `continue-on-error: true` on E2E test steps. Intentional or not, the CI shows green even if the test fails. The 13 `no-timeout-minutes` are mostly informational — Archestra's CI is fast enough that the default 6h cap rarely matters, but the explicit limit is still good hygiene.

A much smaller surface than Next.js — Archestra workflows are well-maintained.

---

## Reproduce

```bash
mkdir -p /tmp/scan && cd /tmp/scan
gh api /repos/<owner>/<repo>/contents/.github/workflows \
  | jq -r '.[] | select(.name | endswith(".yml")) | "\(.name)|\(.download_url)"' \
  | while IFS='|' read name url; do curl -sfo "$name" "$url"; done

# Then run gha-shield over the directory:
git clone https://github.com/Fabridev444/gha-shield && cd gha-shield
node action/index.js   # uses INPUT_PATH from env, defaults to .github/workflows
```

Or in your browser: paste a single workflow at <https://fabridev444.github.io/gha-shield/>.

## Use it in your own CI

```yaml
- uses: Fabridev444/gha-shield@v1.0.0
  with:
    path: .github/workflows
    fail-on: high
```

## Support

This audit took 4 minutes to produce end-to-end against both repos. The rules and the harness are MIT-pending (after V2 ships). If the findings saved your team time, the maintainer accepts USDC tips on Solana to:

`634UtV9dWq8G7ciosqx1pcKkBK4kNkNod9yvoM8ujSdM`

See `.github/FUNDING.yml`. Every tip funds another rule.

## Methodology disclosure

- No manual triage of findings. The numbers above are raw rule outputs; expect false positives proportional to the rule's specificity (low for `unpinned-action`/`hardcoded-secret`, higher for `cmd-injection`/`no-permissions`).
- All scans run locally; no workflow YAML leaves your machine when using the browser tool.
- Tests covering each rule's positive and negative cases live in `scripts/rules.test.mjs` — 45/45 pass at the time of this writing.
