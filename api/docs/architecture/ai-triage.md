# AI triage

AI triage asks a language model for an advisory reading of one finding:
severity assessment, exploitability, business impact, false-positive
likelihood and remediation steps. The result is a suggestion for a person;
it never changes the finding on its own.

Status: shipped. Planned work is listed at the end.

## Flow

```
POST /api/v1/findings/{id}/ai-triage        (button; Member and up, ai_triage:trigger + findings:write)
workflow action trigger_ai_triage            (automation)
auto-triage on manual finding creation       (organization setting)
POST /api/v1/findings/ai-triage/bulk         (deprecated, sunset 2027-01-15)
        │  request-time checks: AI mode, platform provider, AI data policy
        ▼
ai_triage_results row (pending) ──► asynq queue ai_triage ──► worker
        │  AcquireTriageSlot (pending → processing, token limit)
        │  AI data policy again, provider, budget, call, validation
        ▼
completed (activity, audit, workflow event, WebSocket triage:{finding})
or failed (failure code)
```

Key files: `internal/app/aitriage/service.go` (request, worker, auto-triage),
`internal/app/aitriage/errors.go` (failure codes), `internal/app/aipolicy`
(AI data-egress policy), `internal/infra/jobs/ai_triage_tasks.go` (queue
task), `internal/infra/llm` (providers, rate limit),
`internal/infra/http/handler/ai_triage_handler.go`.

## AI data-egress policy

One policy decides whether finding content may leave the platform for a
model, for both AI paths: the organization's own AI application over MCP and
the platform's AI triage (`internal/app/aipolicy`).

- A finding that is not a pentest finding passes.
- A pentest finding passes only when its campaign's TLP is at or below the
  organization's TLP limit for AI (Settings > AI applications, default
  amber) and the campaign lead has not turned AI assistants off.
- A pentest finding without a campaign, or whose campaign cannot be found,
  is refused. A policy or campaign read error refuses (fail closed). Without
  the policy wired, every pentest finding is refused.

AI triage checks the policy at request time (the button, the workflow
action, bulk and auto-triage) and again in the worker right before the call,
so a campaign whose TLP was raised after the request is still kept back. A
refused request answers `403 AI_POLICY_RESTRICTED`; a refused queued job
fails with `ai_policy_restricted`; auto-triage simply does not queue it.

## Errors

The API answers a refused request with a distinct code, never with "no
permission" when the reason is that AI is not available:

| Code | Status | Meaning | Who fixes it |
|---|---|---|---|
| `AI_PLATFORM_NOT_CONFIGURED` | 503 | the organization uses platform AI and no provider is set up | platform administrator (console, System > AI provider) |
| `AI_DISABLED` | 403 | AI triage is off for the organization | organization administrator |
| `AI_POLICY_RESTRICTED` | 403 | the AI data policy keeps this finding on the platform | campaign lead or organization administrator |

A failed triage stores a fixed failure code in `error_message`; the API
returns it as `error_code`, and the web UI translates it. Raw error text
(database, provider, network) is logged on the server only, never stored,
shown, broadcast, sent to workflows or written to the audit log. Rows from
before the codes read as `internal_error`.

Codes: `internal_error`, `ai_policy_restricted`, `provider_not_configured`,
`provider_rate_limited`, `provider_auth_failed`, `provider_quota_exceeded`,
`provider_timeout`, `provider_unavailable`, `content_blocked`,
`input_too_large`, `invalid_response`, `empty_response`, `budget_exhausted`,
`budget_unavailable`, `token_limit_exceeded`, `enqueue_failed`,
`stuck_timeout`, `finding_not_available`.

## Retries

The queue runs up to four attempts (three retries, four minutes each, longer
than one provider call with its own retries).

- A transient failure (`provider_rate_limited`, `provider_timeout`,
  `provider_unavailable`, `budget_unavailable`, `internal_error` before the
  call) puts the row back to `pending` and the queue retries it.
- The last attempt, or any other failure, marks the row `failed` and the
  queue does not retry it.
- A save failure after a successful call is final: the tokens are spent, and
  a retry would pay for the same analysis again.
- The recovery job (`AI_TRIAGE_RECOVERY_*`) fails rows left in pending or
  processing past the stuck duration with `stuck_timeout`.

## What the verdict changes

Nothing automatically. A confident false-positive verdict (likelihood at
least 0.9, no validation warning) on a medium or low finding becomes a
pending false-positive request that a person approves or rejects. The
verdict never changes the priority class. A result with validation warnings
(coerced output, prompt-injection markers in the finding, a proposed
severity change) is flagged `needs_review`, audited, and side-effect
workflows skip it.

## Keys

The console's platform provider key (`platform_settings` key `ai.platform`,
`key_encrypted`) and an organization's own key (`tenants.settings.ai.api_key`)
are in the rekey registry, so rotating `APP_ENCRYPTION_KEY` with `rekey`
carries them over.

## Threat model

- Assets: finding and pentest content, keys, the platform's spend.
- Actors: a scanned target that plants text in HTTP bodies or code (prompt
  injection); a member burning the platform's budget; another organization;
  the provider (retention).
- Controls: nonce-fenced prompt and output validation; no automatic effect
  of a verdict; the AI data-egress policy at request time and in the worker;
  data scope and pentest membership on the routes; tenant-scoped queries
  everywhere; fixed provider URLs through the SSRF-safe client; encrypted,
  write-only keys in the rekey registry; failure codes instead of raw
  errors.

## Planned

Organization opt-in before any data leaves, per-organization budgets and
fair share of the provider rate limit, an organization Settings > AI page,
own-key and self-hosted providers, richer context and a result card with
apply actions (research 196).
