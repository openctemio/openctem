# RFC-119: AI triage governance

| | |
|---|---|
| Status | Accepted (2026-10-19). Partly implemented: one AI data-egress policy for MCP and AI triage, failure codes, the retry contract, organization consent with Settings > AI, monthly platform budgets on by default, per-organization fair share of the platform rate limit, one rate-limit unit per finding in bulk. Designed: own-key (BYOK) and self-hosted providers, context enrichment and redaction, a structured result schema, the result card with apply actions, "Triage selected" bulk, the evaluation set |
| Scope | api (`internal/app/aipolicy`, `internal/app/aitriage`, `internal/infra/llm`, tenant settings `ai`, `/api/v1/tenants/{tenant}/settings/ai`), web (Settings > AI, the AI triage button and result) |
| Related | RFC-016 / RFC-062 (MCP and its organization policy, the TLP limit for AI), RFC-008 (token budgets); `docs/architecture/ai-triage.md` |

## 1. Problem

AI triage sends a finding's title, description and code snippet to a
language model. Until now:

- the organization's AI data policy (pentest TLP limit, campaign AI switch)
  applied to MCP only;
- no organization agreed to it: once a platform administrator set up a
  provider, any member of any organization could send content;
- the platform's spend had no default cap, bulk spent one rate-limit unit
  for up to 100 calls, and one organization could use the whole provider
  allowance;
- raw internal errors reached the UI, WebSocket and audit log; retries never
  ran; an AI verdict could lower a finding's priority on its own.

## 2. Decisions

| # | Decision |
|---|---|
| D1 | AI triage is off for an organization until an organization administrator turns it on. Organizations that already used it stay on (migration, audited). |
| D2 | Organizations may use their own key in every edition (designed). |
| D3 | Local and self-hosted models through one OpenAI-compatible provider with a base URL (designed). |
| D4 | A small default monthly platform budget; an own key is not counted. |
| D5 | Pentest content follows the same organization policy as MCP. |
| D6 | An AI verdict never changes the priority class; it stays a suggestion (false-positive proposals go to a person). |
| D7 | The deprecated bulk route is replaced by "Triage selected" on the same queue (designed). |
| D8 | Members may trigger single triage once the organization opted in; bulk also needs `findings:bulk_update`. |

## 3. Design (implemented part)

- **One egress policy** (`internal/app/aipolicy`): a pentest finding passes
  only when its campaign is at or below the organization's TLP limit for AI
  and its lead has not turned AI off. It fails closed. MCP and AI triage
  call it; AI triage checks at request time and again in the worker.
- **Consent**: `settings.ai.enabled_at` / `enabled_by`. The effective mode is
  `disabled` until set. `GET/PUT /api/v1/tenants/{tenant}/settings/ai`
  (owners and administrators, `settings:write`, a recent sign-in), audited
  as critical (`ai_settings.updated`). The worker re-checks consent, so
  turning it off stops queued jobs. Migration 003140 keeps organizations with
  triage results on (`enabled_by = upgrade`, audit `ai_settings.opt_in_migrated`).
- **Availability**: a provider key (environment or console) makes platform AI
  available; `AI_TRIAGE_ENABLED` is removed. `GET /findings/ai-triage/config`
  answers `is_enabled` plus a `reason` (`not_enabled`,
  `platform_not_configured`, `budget_exhausted`); the request routes answer
  `AI_DISABLED`, `AI_PLATFORM_NOT_CONFIGURED` or `AI_POLICY_RESTRICTED`.
- **Cost**: the monthly budget (`ai_triage_budgets`) is on by default with
  2,000,000 tokens per organization and month for platform AI
  (`AI_TRIAGE_BUDGET_*`). Each organization has its own bucket
  (`AI_RATE_LIMIT_TENANT_RPM`, default 20) in front of the platform key's
  shared one (`AI_RATE_LIMIT_RPM`). A bulk request spends one HTTP rate-limit
  unit per finding.
- **Errors and retries**: fixed failure codes instead of error text; a
  transient failure is retried by the queue, the last attempt fails the row.

## 4. Threat model

- A member sending content the organization did not agree to send:
  consent, checked at request time and in the worker.
- Pentest content above the organization's TLP limit: the shared egress
  policy on every path, failing closed.
- Cost burn of the platform key and a noisy neighbour: the monthly budget,
  the fair-share bucket, per-finding rate limit units.
- Information disclosure through errors: failure codes only.
- Prompt injection through scanned content: fenced prompt, output validation,
  and no automatic effect of a verdict.
- Tenant isolation: the tenant comes from the authenticated principal;
  every query is tenant-scoped; the consent route is the organization's own.

## 5. Not built

A chat assistant, autonomous agents, fine-tuning, embeddings, a per-tenant
prompt editor, an AI gateway service, and any AI that writes to findings
without a person.
