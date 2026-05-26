# Real-world `--fix` usage

These are unedited drive-by PRs opened against active OSS repos using `npx Fabridev444/gha-shield .github/workflows --fix`. Each PR pinned every unpinned action to a commit SHA in a single mechanical pass, with the original tag preserved as a trailing `# vN` comment for Dependabot.

| Repo | PR | Findings cleared | Critical pin |
|------|----|------------------|--------------|
| [`DNSCrypt/dnscrypt-proxy`](https://github.com/DNSCrypt/dnscrypt-proxy) | [#3231](https://github.com/DNSCrypt/dnscrypt-proxy/pull/3231) | 11 / 11 `unpinned-action` HIGH | CodeQL workflow + release pipeline (signs binaries) |
| [`node-schedule/node-schedule`](https://github.com/node-schedule/node-schedule) | [#759](https://github.com/node-schedule/node-schedule/pull/759) | 10 / 10 `unpinned-action` HIGH | `coverallsapp/github-action@master` (branch ref, force-pushable) |
| [`anza-xyz/wallet-adapter`](https://github.com/anza-xyz/wallet-adapter) | [#1154](https://github.com/anza-xyz/wallet-adapter/pull/1154) | 10 / 10 `unpinned-action` HIGH | `changesets/action@v1` receiving `NPM_TOKEN` on push to `master` |

## Why these three

They're not cherry-picked for visibility — they're concrete demonstrations of the three classes of exposure `--fix` closes:

1. **Security tooling that itself runs unpinned actions**. DNSCrypt is a crypto/DNS-privacy project; its CodeQL workflow runs on every PR with broad scope. A rewritten `github/codeql-action/init@v4` would mean attacker-controlled code execution on every contributor's PR build.

2. **Mutable branch references (`@master`)**. node-schedule's coverage workflow pulled `coverallsapp/github-action@master` — `master` can be force-pushed by anyone with push access to the action's repo. Pinning to a SHA closes the window.

3. **Publish workflows with secrets**. wallet-adapter publishes `@solana/wallet-adapter-*` npm packages. `release.yml` passes `NPM_TOKEN` to `changesets/action@v1`. Rewriting that tag (cf. [tj-actions/changed-files CVE-2025-30066](https://nvd.nist.gov/vuln/detail/CVE-2025-30066)) exfiltrates publishing access to ~50 packages depended on by every Solana dApp.

## How to run this on your repo

```bash
# Read-only scan first
npx Fabridev444/gha-shield .github/workflows

# When you're ready to commit
npx Fabridev444/gha-shield .github/workflows --fix
git diff
```

Set `GH_TOKEN` (or `GITHUB_TOKEN`) in env to use the authenticated rate limit (5000/hr vs 60/hr anonymous). The tool only reads from `repos/<owner>/<repo>/commits/<ref>` — no write access required.

## What Dependabot will do next

`--fix` writes the pinned action as `actions/checkout@<sha40> # v4`. Dependabot's `github-actions` ecosystem reads the trailing `# vN` comment and continues to update both the SHA and the comment when a new minor/major arrives. No new config needed if you already have `.github/dependabot.yml`.

If you don't, the [minimal three-line config](https://github.com/Fabridev444/gha-shield/blob/main/.github/dependabot.yml) is checked into this repo as reference.

## Tip the maintainer

`gha-shield` is MIT (V2+) and self-hosted via `npx Fabridev444/gha-shield`. If it saved you a CVE, drop a USDC tip — [scannable QR + Solana Pay link in README](./README.md#tip-the-maintainer-solana--usdc-spl), or directly: `634UtV9dWq8G7ciosqx1pcKkBK4kNkNod9yvoM8ujSdM`.
