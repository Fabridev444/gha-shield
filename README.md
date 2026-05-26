# gha-shield

[![CI](https://github.com/Fabridev444/gha-shield/actions/workflows/ci.yml/badge.svg)](https://github.com/Fabridev444/gha-shield/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Fabridev444/gha-shield)](https://github.com/Fabridev444/gha-shield/releases)
[![Try in browser](https://img.shields.io/badge/browser-fabridev444.github.io%2Fgha--shield-4ade80)](https://fabridev444.github.io/gha-shield/)
[![Tests](https://img.shields.io/badge/tests-48%2F48%20passing-4ade80)](https://github.com/Fabridev444/gha-shield/blob/main/scripts/rules.test.mjs)

GitHub Actions workflow security scanner. Paste a YAML, get a security report in 5 seconds. No CLI install, no GitHub App permissions, no logs.

## What it catches (V1, free tier)

Thirteen hard-coded rules that run entirely in the browser:

| Rule | Severity | Detects |
|------|----------|---------|
| `unpinned-action` | HIGH | Third-party action pinned to a tag/branch instead of a 40-char commit SHA. |
| `prtarget-checkout-prref` | CRIT | `pull_request_target` trigger combined with `actions/checkout` of an attacker-controlled ref. |
| `cmd-injection` | CRIT | `${{ github.event.* }}`, `head_ref`, or `inputs.*` expanded inside a `run:` shell block. |
| `no-permissions` | MED | Workflow has external triggers but no `permissions:` block — `GITHUB_TOKEN` defaults to broad scope. |
| `continue-on-error-auth` | HIGH | `continue-on-error: true` on a step whose name/run hits `auth\|login\|test\|lint\|audit\|security`. |
| `secret-in-if` | MED | `secrets.*` referenced inside an `if:` expression — leaked to logs under `ACTIONS_STEP_DEBUG=true`. |
| `curl-pipe-bash` | HIGH | `curl/wget/fetch ... \| bash/sh/python/node/ruby/perl` — remote endpoint controls what executes on your runner. |
| `untrusted-download` | MED | Download from gist/raw.github/pastebin/transfer.sh **without** a checksum command in the same step. |
| `scheduled-broad-perms` | MED | `schedule:` trigger without tight `permissions:` — runs nightly with default broad token, no PR review gate. |
| `workflow-run-untrusted-checkout` | CRIT | `workflow_run` trigger + `actions/checkout` of the triggering workflow's ref — privilege-escalation cousin of `pull_request_target`. |
| `hardcoded-secret` | CRIT | Provider-prefixed key (sk-, sk_live_, ghp_, AKIA…) hard-coded in `env:`, OR long opaque value under a secret-named env key. |
| `third-party-action-token` | HIGH/MED | Untrusted-owner action (not `actions/*`/`github/*`/`docker/*`) receives `GITHUB_TOKEN` (HIGH) or any other `secrets.*` value (MED) via `with:`. |
| `no-timeout-minutes` | LOW | Job on an externally-triggered workflow has no `timeout-minutes` (default 6h burns minutes quota on hangs/loops). |

## Three ways to run it

**1. In your browser** (zero install):
```
https://fabridev444.github.io/gha-shield/
```

**2. As a CLI** (no install, runs from GitHub via npx):
```bash
npx Fabridev444/gha-shield                   # scans ./.github/workflows
npx Fabridev444/gha-shield path/file.yml     # single file
npx Fabridev444/gha-shield . --format=json   # JSON to stdout
npx Fabridev444/gha-shield --fail-on=crit    # custom threshold
```

**3. As a GitHub Action** (in your CI):
```yaml
- uses: Fabridev444/gha-shield@v1.0.1
  with:
    path: .github/workflows
    fail-on: high
```

## What's coming (Pro tier, $9 one-time)

Three high-leverage extras that ship with V2:

- **Bulk scan** — paste a folder/glob of `.github/workflows/*.yml` instead of one file at a time; report aggregated by rule with per-file drill-down.
- **LLM-driven advanced patterns (BYOK)** — cross-job credential propagation, suspicious script idioms (eval/base64-exec), dev/prod secret confusion based on naming, with specific safer rewrites suggested per finding.
- **PDF report export** — full report with TOC, severity histogram, suitable for security review handoff.

Stripe checkout wiring ships in V2.

## File layout

```
gha-shield/
├── index.html             — landing + scan UI (no build)
├── scripts/
│   ├── rules.js           — 13 free rules (pure ESM, yaml@2 via esm.sh)
│   ├── main.js            — DOM glue: scan button, render, template clone
│   ├── rules.test.mjs     — node --test unit tests (45 cases)
│   └── e2e-real.mjs       — scans `.github/workflows/*` of any cloned repo
├── spec.md                — product spec + V1 scope
└── README.md              — this file
```

## Run locally

```bash
cd <this-dir>
python3 -m http.server 8765
open http://localhost:8765
```

Paste any workflow YAML into the textarea, click **Scan**.

For a quick sanity check from the terminal:

```bash
curl -sI http://localhost:8765/index.html | head -1   # expect: HTTP/1.0 200 OK
```

## Run the unit tests

```bash
cd scripts
node --test rules.test.mjs
```

Expected: `45 pass, 0 fail, ~100ms`. The test harness reads `rules.js`, strips the `esm.sh` import (node refuses HTTPS imports without a flag), and evals the module in an isolated `Function` scope to exercise `runFreeRulesParsed` directly with hand-crafted ASTs.

## Deploy (Cloudflare Pages — V1)

Requires `B5` (a Cloudflare account, free tier).

```bash
# One-time:
npm install -g wrangler
wrangler login                   # opens browser, paste account credentials

# Per-deploy:
wrangler pages deploy . --project-name=gha-shield --branch=main
```

Output is a `*.pages.dev` URL. Hand it to early users.

V2 deploy will add a Cloudflare Worker for the Stripe webhook handler and the Pro endpoint that forwards LLM requests using the buyer's BYOK key.

## Roadmap

- [x] V0 — spec + decision lock (`spec.md`).
- [x] V1.0 — landing + 13 free rules + 45 unit tests + E2E scan of 23 real archestra workflows (15 findings: 13 LOW timeout + 2 HIGH continue-on-error).
- [ ] V1.1 — Cloudflare Pages deploy at `gha-shield.pages.dev` (requires B5).
- [ ] V1.2 — Hand-deliver the link to 3 friends + r/devops post for first reactions.
- [ ] V2.0 — Stripe Checkout one-time $9, Worker that gates Pro features behind `session_id` cookie.
- [ ] V2.1 — Bulk scan (glob/folder input) + per-file aggregated report.
- [ ] V2.2 — LLM patterns (BYOK): cross-job-creds, dangerous-script-idioms, dev-prod-confusion, safer-rewrite-suggestions.
- [ ] V2.3 — PDF report export from the report view.
- [ ] V3 — `Watch` tier ($5/mo): GitHub App, webhook on push to `.github/workflows/*`, 14-day history.


## Real-world audits

See [REAL-WORLD-AUDITS.md](./REAL-WORLD-AUDITS.md) — unedited scan results from running gha-shield over the public workflows of `vercel/next.js` (87 findings, 4 crit) and `archestra-ai/archestra` (15 findings). Methodology + reproducer commands included.

## Why this exists (the one-line version)

`octoscan` exists. `actionlint` exists. Spectral has a security ruleset. Each one wants you to install a CLI, learn its flag set, integrate it into CI, and read the JSON output yourself. gha-shield is the 5-second answer for the case where you just want to know whether the workflow in your scratch tab is unsafe to merge.

## Tip the maintainer (Solana / USDC SPL)

If gha-shield saved you a CVE, drop a tip. Scan the QR with any Solana wallet (Phantom, Backpack, Solflare) — it auto-fills the recipient + USDC SPL mint via [Solana Pay](https://docs.solanapay.com/spec):

<a href="solana:634UtV9dWq8G7ciosqx1pcKkBK4kNkNod9yvoM8ujSdM?spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&label=gha-shield&message=Tip%20for%20gha-shield"><img src="./docs/tip-qr.svg" alt="Solana Pay QR — gha-shield tip jar" width="220" /></a>

- **Wallet**: `634UtV9dWq8G7ciosqx1pcKkBK4kNkNod9yvoM8ujSdM`
- **Token**: USDC SPL (`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`)
- **Pay link**: [`solana:634UtV9dWq8G7ciosqx1pcKkBK4kNkNod9yvoM8ujSdM?spl-token=…`](solana:634UtV9dWq8G7ciosqx1pcKkBK4kNkNod9yvoM8ujSdM?spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&label=gha-shield&message=Tip%20for%20gha-shield)

No KYC, no Stripe Connect, no minimum. Settles in ~400ms on Solana mainnet.

## License

V0/V1 source is private until product/market validated. After V2.1 the 6 free rules + harness will be released under MIT; the 4 Pro LLM rules remain behind paywall.

## Refund policy

30 days, no questions asked. Click the refund button in your Gumroad/Stripe receipt.
