# H9 — gha-shield (GitHub Actions security scanner SaaS)

## Decisión razonada del nicho

Filtré 5 candidatos por: mercado, AI-doable, diferenciador defensible vs free competitors, costo marginal, time-to-first-sale.

| Candidato | Free competitor dominante | Diferenciador real | Decision |
|-----------|---------------------------|-------------------|----------|
| Regex-from-examples | regex101 (20 años) | weak — Claude oversmart en regex simple | descarte |
| SQL-from-schema | ChatGPT gratis | weak — todos lo hacen | descarte |
| Cron-explainer | crontab.guru | weak — marca dominante | descarte |
| JSON-Schema-from-sample | quicktype.io | weak | descarte |
| README-from-package.json | readme.so | weak — templates ya cubren | descarte |
| **GHA workflow security scan** | **Spectral/octoscan/CLI** | **strong — UX-pulida + LLM-driven contextual rules + monitoring webhook** | **PICK** |
| OpenAPI validator | Spectral | medium | reserva |
| Schema visualizer + index recommender | dbdiagram.io | medium | reserva |

**Por qué GHA security scanner:**
1. **Mercado claro y motivado**: supply chain attacks en aumento desde 2023 (XZ, npm event-stream, ua-parser-js). Cada equipo grande hace audits.
2. **Free competitors existen pero son CLI o complejos**: `octoscan`, `actionlint` requieren install + lectura de docs. Mi UX = paste yaml → reporte legible en 5s.
3. **Costo marginal cero**: BYOK (Bring Your Own Key) — usuario aporta su Anthropic/OpenAI API key, yo no pago tokens. Constraint de Fabri respetado: cero APIs pagas mías.
4. **Conversion path natural**: free 1 workflow scan → friction at "scan all workflows + monthly monitoring webhook" → $9 one-time o $5/mes.

## Arquitectura

```
Browser (HTML+vanilla JS)
   ↓ paste YAML + own API key (kept client-side)
   ↓
Cloudflare Pages (static hosting, free tier)
   ↓
Serverless function (Cloudflare Workers, free tier ≤100k req/day)
   ↓ calls LLM provider on user's behalf with user's own key
   ↓
LLM response → structured findings JSON
   ↓
Render report (free) | Stripe paywall (paid features)
```

**Key data flow:**
- API key NEVER stored. User pastes once per session, kept in browser memory.
- Worker only proxies. No logs of API key, no logs of yaml content.
- Paid features (multi-workflow + webhook) require Stripe email → Cloudflare KV stores email + subscription state + webhook URL.

## Reglas de seguridad escaneadas

**Free tier (10 hard-coded, vanilla JS, no LLM call):**
1. `unpinned-action` — third-party actions not SHA-pinned.
2. `prtarget-checkout-prref` — `pull_request_target` + checkout of attacker-controlled ref.
3. `cmd-injection` — `${{ github.event.* }}` interpolated into `run:` shell.
4. `no-permissions` — external trigger without explicit `permissions:` block.
5. `continue-on-error-auth` — `continue-on-error: true` on auth/test/lint/audit steps.
6. `secret-in-if` — `secrets.*` referenced inside `if:` expression (debug-log leak).
7. `curl-pipe-bash` — remote script piped directly to a shell (`curl | bash`).
8. `untrusted-download` — gist/raw.github/pastebin download without checksum verification.
9. `scheduled-broad-perms` — `schedule:` trigger with missing or write-broad token.
10. `workflow-run-untrusted-checkout` — `workflow_run` + checkout of triggering workflow's ref.

**Pro tier ($9 one-time, V2):**
- Bulk scan: paste a folder/glob of `.github/workflows/*.yml` at once; aggregated report.
- LLM patterns (BYOK — Claude/GPT key supplied by user):
  - Cross-job credential propagation without scope tightening.
  - Script anti-patterns (eval, base64-then-exec, untyped untrusted JSON parsing).
  - Dev/prod secret naming confusion.
  - Specific safer rewrite suggestions per finding.
- PDF export with TOC + severity histogram.

## Pricing model

| Tier | Price | What | Friction |
|------|-------|------|----------|
| Free | $0 | 10 hard-coded rules, single-file scan | None |
| Pro | $9 one-time | Bulk-scan folder, LLM patterns (BYOK), PDF export, all 10 free rules | Stripe checkout 1× |
| Watch | $5/mo | Webhook scanning of `.github/workflows/` on push, 14-day history | Stripe subscription + GitHub App install |

Watch tier deferred to V2 (requires Stripe + Cloudflare KV setup + GitHub App). V1 = free + Pro one-time only.

## V1 build scope (next ticks)

1. **Frontend** (`index.html`):
   - 2 columns: YAML paste + API key paste + button → report.
   - Report: cards by severity (critical/high/medium/low/info).
   - Stripe Buy button gate for paid rules.
2. **Worker** (`worker.js`):
   - Endpoint `/scan-free`: takes YAML, runs hard-coded rules 1-6, returns JSON.
   - Endpoint `/scan-pro`: requires Stripe `session_id` cookie + user's API key, runs rules 7-10.
3. **Stripe Checkout**:
   - 1 product `gha-shield-pro`, $9 one-time, success returns `session_id` to set cookie.
4. **Verify-pay endpoint**:
   - Worker calls Stripe API to confirm session before serving paid endpoints.

## Blockers nuevos requeridos

**B5** — Cloudflare account + Pages + Workers free tier. Fabri 5min signup at cloudflare.com.
**B6** — Domain. Either `.workers.dev` subdomain (free, ugly) or a real domain ($10-15/year, gasto requiere aprobación). V1 ship en `.workers.dev` is fine.
**B7** — Stripe paid mode activated (depends on B2). For V1 testing, Stripe test mode is fine (test cards, no real money).

## Próximas acciones (ticks 31-N)

- T31: scaffold `index.html` con UI mockup completo.
- T32: implementar hard-coded rules 1-6 en pure JS.
- T33: write `worker.js` con endpoint `/scan-free`.
- T34: deploy a `.workers.dev` (necesita B5).
- T35-T40: paid features (rules 7-10), Stripe integration, BYOK flow.
