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

## `prisma/prisma` — 17 workflows, 139 findings

Scanned: 2026-05-26, `main` branch.

```
By rule id (desc):
  unpinned-action            89   (HIGH)
  third-party-action-token   27   (HIGH/MED)
  no-timeout-minutes          9   (LOW)
  no-permissions              8   (MED)
  scheduled-broad-perms       3   (MED)
  continue-on-error-auth      2   (HIGH)
  cmd-injection               1   (CRIT)
```

**89 unpinned actions in 17 workflows** is the densest unpinned-action count in this corpus. Every third-party action is referenced by tag rather than 40-char commit SHA. The tag → SHA migration is mechanical (Dependabot can keep them fresh), but the surface as it stands today means every CI run trusts the current maintainer of each tagged action not to retag malicious code.

The 27 `third-party-action-token` findings are concentrated in update workflows (`update-studio-version.yml`, etc.) that hand a token to non-`actions/*`-owner actions. The 1 CRIT `cmd-injection` is a single isolated instance after the rule 3 v1.0.1 SAFE_LEAF_FIELDS cleanup.

---

## `oven-sh/bun` — 30 workflows, 59 findings

Scanned: 2026-05-26, `main` branch, after the rule 3 v1.0.1 false-positive cleanup.

```
By severity:
   0 CRIT
  11 HIGH
  27 MED
  21 LOW
```

11 HIGH findings concentrate on `third-party-action-token` — third-party actions in workflows like `update-vendor.yml` and `update-zstd.yml` receiving `GITHUB_TOKEN`. Recommended mitigation per the rule fix: vendor the action's logic into a local `./.github/actions/*` and audit it, or use a narrowly-scoped PAT.

The 27 MED + 21 LOW are mostly the `no-permissions` and `no-timeout-minutes` clusters across automation workflows.

---

## `astral-sh/uv` — 27 workflows, 12 findings

Scanned: 2026-05-26, `main` branch.

```
By rule id:
  third-party-action-token   9   (3 HIGH + 6 MED)
  curl-pipe-bash             1   (HIGH)
  no-timeout-minutes         2   (LOW)
```

The two HIGH `third-party-action-token` findings are both in `build-release-binaries.yml` (`jobs.linux-riscv64.steps[4|9].with.githubToken`) — actions outside the trusted owners list (`actions/*`, `github/*`, `docker/*`) receiving `GITHUB_TOKEN`. The narrow PAT recommendation in the rule's fix message applies.

The HIGH `curl-pipe-bash` is in `test-system.yml`, the pyenv install step. Common pattern across many Python projects — pyenv's official installer ships as a curl-piped script. Mitigation per the rule: download to a file first, verify the published SHA, then execute.

The 6 MED `third-party-action-token` findings cover AWS, Google Cloud, and trigger tokens passed to community actions. False-positive risk is moderate — `aws-actions/*` and `google-github-actions/*` are arguably as trustworthy as the official `actions/*` owners, but the rule keeps the trusted-owner list deliberately small. Recommendation: extend the trusted-owner allowlist as a follow-up rule option.

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
