# Launch posts for gha-shield V1.1

Pegar tal cual cuando el deploy a `gha-shield.pages.dev` esté arriba (depende de B5). Sustituí `URL` por el dominio final antes de postear.

---

## Hacker News — Show HN

**Title** (max 80 chars, no all-caps, no emoji):
```
Show HN: gha-shield – paste a GitHub Actions workflow, get a security report
```
(73 chars)

**Body** (HN renders plain text + markdown links; keep paragraphs short):
```
Hi HN — gha-shield is a 5-second answer for "is the workflow in my scratch tab safe to merge?"

Paste a `.yml` from `.github/workflows/`, click Scan, get 13 categorized findings: unpinned actions, `pull_request_target` + PR checkout, `${{ github.event.* }}` interpolation in run blocks, missing `permissions:`, `curl | bash`, scheduled workflow with broad token, hard-coded provider keys (sk-…, ghp_…, AKIA…), untrusted action receiving GITHUB_TOKEN, and five more.

Why it exists when `octoscan`, `actionlint`, and Spectral are CLI tools: I wanted the case where I just have a workflow open in another tab and want the answer in 5 seconds without installing anything or learning a flag set.

The 13 rules run entirely in your browser. No backend, no logs, no GitHub App permissions, no signup. YAML stays in the page; the only network call is loading the `yaml` parser (esm.sh, cached).

Pro tier ($9 one-time, ships when V2 lands): bulk-scan a whole folder, LLM-driven advanced patterns via your own Anthropic/OpenAI key (BYOK, never logged), PDF export. The 13 free rules stay free forever.

Receipts (no claims without data):
- Ran it over `archestra-ai/archestra` (23 workflows): 15 findings, 2 legit `continue-on-error: true` on test steps.
- Ran it over `vercel/next.js` (37 workflows): 87 findings, including 4 CRIT in a single release workflow (`release-next-rspack.yml`) and 15 candidate command-injection patterns.
- Tests: 45/45 unit (`node --test`) + 2 E2E sweeps on the above repos.

Built it because I needed it for bounty hunting. Feedback welcome — every false positive becomes a regression test in `rules.test.mjs`.

<URL>
```

**Suggested submit window:** Tue–Thu, 08:00–11:00 PT (highest active-user density on HN historically). Avoid weekends and Mon US holidays.

---

## Twitter / X — 5-tweet thread

**Tweet 1** (hook, ≤280 chars):
```
shipped gha-shield — paste any github actions workflow, get a security report in 5 seconds.

11 rules, browser-only, no signup, no logs. it's the answer for "is this workflow safe to merge" when octoscan/actionlint feels like overkill.

<URL>
```
(264 chars including url placeholder)

**Tweet 2** — "what it catches" (visual list, easy reshare):
```
the 11 free checks:

· unpinned actions (no SHA)
· pull_request_target + PR checkout
· ${{ github.event.* }} in run blocks
· missing permissions:
· curl | bash
· schedule: + broad token
· hard-coded sk-… / ghp_… / AKIA…
· workflow_run untrusted checkout
+3 more
```
(279 chars)

**Tweet 3** — credibility (dogfood, with the next.js receipt):
```
ran it over vercel/next.js (37 workflows in their .github/workflows/).

87 findings. 4 CRITICAL in release-next-rspack.yml alone. 15 candidate command-injection patterns.

45/45 unit tests, 2 E2E sweeps. every false positive becomes a regression test.
```
(279 chars)

**Tweet 4** — pricing reveal:
```
free: 11 rules, single-file scan, forever
$9 one-time (when stripe wires up): bulk-scan a folder, 4 LLM-driven patterns via your own anthropic/openai key (BYOK, never logged), PDF export

no subscription. no telemetry. no github app permissions.
```
(265 chars)

**Tweet 5** — call to action:
```
try it: <URL>
source for the free rules: <URL>/source
file any false positive: each one becomes a test

if you maintain a repo with .github/workflows/, please run a scan — would love to know what i'm missing.
```
(254 chars)

---

## Reddit — /r/devops self-post

**Title:**
```
[Tool] gha-shield: paste a workflow YAML, get a GitHub Actions security report (11 browser-only rules, no signup)
```

**Body:**
```
Built this because I kept wanting to know whether a workflow in another tab was safe to merge, without installing octoscan / actionlint / Spectral and learning flags.

Paste `.github/workflows/*.yml` → 11 categorized findings in ~1 second:

* unpinned third-party actions (no SHA)
* `pull_request_target` + checkout of attacker-controlled ref (the classic privilege escalation)
* `${{ github.event.* }}` expansion into `run:` shell
* missing `permissions:` block on external triggers
* `curl | bash` / `wget | sh`
* `secrets.*` inside `if:` (debug-log leak)
* hardcoded provider keys in `env:` (sk-, ghp_, AKIA, …)
* scheduled workflow with broad token
* `workflow_run` + untrusted checkout
* `continue-on-error: true` on auth/test/lint steps
* gist/raw/pastebin downloads without checksum

100% browser-side. YAML never leaves your tab. The only network call is loading the YAML parser (esm.sh, cached). No backend, no GitHub App, no signup.

Tested against:
- `archestra-ai/archestra` (23 workflows): 15 findings.
- `vercel/next.js` (37 workflows): 87 findings, 4 CRIT in `release-next-rspack.yml`.

45/45 unit tests (`node --test`).

Free forever. A $9 one-time Pro tier ships in V2 with bulk-scan, LLM-driven patterns (BYOK key), and PDF export.

URL: <URL>

Comment with a workflow where you think the rules will miss or false-positive — I add a regression test for every one.
```

---

## LinkedIn — for an eventual professional/B2B angle

**Body (no character limit but keep tight):**
```
Shipped a small tool today: gha-shield. Paste a GitHub Actions workflow YAML, get an 11-rule security report in your browser — no install, no signup, no logs.

I built it for the case where I just want to know whether a workflow in another tab is safe to merge, without firing up octoscan or actionlint and reading their flag set.

What it catches: unpinned actions, pull_request_target + PR checkout, command injection via `${{ github.event.* }}`, missing `permissions:` blocks, curl | bash, hard-coded provider keys (sk-…, ghp_…, AKIA…), scheduled workflows with broad tokens, and more.

11 rules total today. Free forever. A $9 Pro tier with bulk scanning, LLM-driven advanced patterns (your own API key, never logged), and PDF export is coming.

Built it because I needed it. If you maintain a repo with .github/workflows/, run a scan — I'd love to know what I'm missing.

<URL>
```

---

## Email outreach template (3 specific dev influencers — fill in names)

Subject: `quick scan for <repo>?`

```
hey <name>,

shipped a small thing — gha-shield is a 5-second GitHub Actions workflow security scanner. paste yaml, get 11-rule report, browser-only, no signup: <URL>

would love a 10-second test against <their-repo>/.github/workflows/* — the rules catch unpinned actions, pull_request_target + PR checkout, ${{ github.event.* }} in run blocks, hard-coded keys in env, and a few more.

if anything false-positives, i add a regression test. if anything legit slips through, i add a rule.

no ask other than "try it once" — would mean a lot.

<your-name>
```

Targets to consider (manually curate based on Fabri's network):
- maintainers of well-known TS/Node repos who have written about CI hygiene.
- security-tooling indie devs who built `octoscan` / `actionlint` etc. (could be reciprocal mention).
- people who tweet about supply chain attacks regularly.

NOT contacting: random cold lists, scraped emails, bulk anything. Spam violates the macro restrictions.

---

## Launch-day checklist

- [ ] B5 done: `gha-shield.pages.dev` returns 200 with the index page.
- [ ] Substitute `<URL>` placeholders above with the real URL.
- [ ] Soft-launch first: post to 1 person you trust, get a real reaction, fix anything embarrassing.
- [ ] HN post during the 08:00–11:00 PT Tue–Thu window.
- [ ] Tweet thread starts 30 min after HN goes live (so first replies on HN can be referenced).
- [ ] Reddit /r/devops post within 4 hours of HN.
- [ ] LinkedIn / email outreach the next day, NOT same day (split the load).
- [ ] Watch the comments. Reply to every legit feedback within 24h.
- [ ] First refund request: read it, no fight, refund. Record reason in `feedback.md`.
