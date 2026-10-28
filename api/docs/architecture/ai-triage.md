# AI triage

AI triage asks a language model for an advisory reading of one finding:
severity assessment, exploitability, business impact, false-positive
likelihood and remediation steps. The result is a suggestion for a person;
it never changes the finding on its own.

Status: shipped. Planned work is listed at the end. Design and decisions:
[RFC-119](../rfcs/RFC-119-ai-triage-governance.md).

> The sub-modules `ai_triage.bulk`, `.auto`, `.workflow`, `.byok`, `.agent` and
> `.custom_prompts` were removed (migration 003493). The feature is gated by
> the `ai_triage` module and the `ai_triage:*` permissions only. Model output is
> a suggestion stored on the triage result; the service never writes a
> finding's severity or priority (guarded by `no_human_free_change_test.go`).

## Who turns it on

- **Platform administrator**: sets up the platform AI provider in the
  console (System > AI provider: provider, model, write-only key; for a
  self-hosted or gateway model, the `openai_compatible` provider with a base
  URL and an optional key), or with
  an environment key (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
  `GEMINI_API_KEY`), which pins the provider. A key makes platform AI
  available; nothing is sent until an organization turns AI triage on.
- **Organization administrator** (owner or administrator): turns AI triage
  on or off for the organization in Settings > AI
  (`GET/PUT /api/v1/organization/settings/ai`, `settings:write`, a recent
  sign-in, audited as critical `ai_settings.updated`). Turning it on is the
  organization's consent to send finding content, within its AI data policy,
  to the provider. It is stored in `tenant_ai_settings` (`enabled_at`,
  `enabled_by`); until then the effective mode is `disabled`. The worker checks consent
  again, so turning it off stops jobs already queued (`ai_disabled`).
- **Upgrade**: migration 003140 keeps AI triage on for organizations that
  already had a triage result (`enabled_by = upgrade`, one audit row
  `ai_settings.opt_in_migrated` each); every other organization starts off.
- **Members**: the AI triage button (`ai_triage:trigger` and
  `findings:write`); bulk also needs `findings:bulk_update`.

`GET /api/v1/findings/ai-triage/config` tells the web UI whether the button
works (`is_enabled`) and, when not, why: `not_enabled` (an organization
administrator turns it on in Settings > AI), `platform_not_configured` (a
platform administrator sets up a provider in the console) or
`budget_exhausted`. It also returns the month's platform token use and limit.

## Web UI

- **Settings > AI** (`web/src/app/(dashboard)/settings/ai`, Security group,
  module `ai_triage`): the on/off switch with a consent dialog, what is sent,
  the pentest data policy, the source (Platform AI, Own provider, Off) with the
  own provider's form (write-only key, Test connection) and the month's token use. Read-only
  for anyone who may not change it; a notice when no provider is set up.
- **AI triage button** (finding header): hidden when the module is off. When
  AI cannot run, it stays visible but disabled-looking and opens a short
  explanation instead: off for the organization (owners and administrators
  get a link to Settings > AI, members are told to ask one), no provider on
  the installation (a platform administrator sets it up in the console), or
  the monthly allowance used up. A refused request (for example
  `AI_POLICY_RESTRICTED`) and a failed triage show a translated message for
  their code; one toast per run.
- The Overview tab shows the false-positive likelihood (older activity rows,
  which stored the model's confidence that the finding is real, are shown as
  the inverse band).

## Cost controls

- Monthly budget per organization for platform AI (`ai_triage_budgets`), on
  by default: 2,000,000 tokens per month (`AI_TRIAGE_BUDGET_ENABLED`,
  `AI_TRIAGE_BUDGET_DEFAULT_TOKENS`, set on the month's row when it is
  created). A triage that would pass it fails with `budget_exhausted`. The
  cap counts every organization's tokens, with the platform key or its own.
  This is deliberate: an organization on its own provider is also stopped at
  the cap, so an administrator can use it as a spend limit on the organization's
  own account. The cap is set by the platform administrator.
- Provider rate limit: `AI_RATE_LIMIT_RPM` per provider key, and each
  organization's own bucket in front of the platform key's
  (`AI_RATE_LIMIT_TENANT_RPM`, default 20), so one organization cannot starve
  the others.
- HTTP rate limit: 10 triage requests per minute per organization and
  replica; a bulk request spends one unit per finding and is refused (429)
  past the allowance.

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

## What an AI reviewer may see

Any AI that reviews or approves something (triage today, a draft reviewer or a check of an outside agent's proposal later) receives the object under review and input a person wrote, and nothing else. It never receives the requesting agent's transcript or free-text justification as instructions. A justification an agent supplies is shown to the person who decides, fenced as untrusted text, and is never offered to the reviewing model as authority. Content that came from scanners, tested systems or outside agents sits inside a per-request fence the model is told to treat as data, and a model verdict stays advisory: it can add a warning or a proposal, and a person decides.

## Errors

The API answers a refused request with a distinct code, never with "no
permission" when the reason is that AI is not available:

| Code | Status | Meaning | Who fixes it |
|---|---|---|---|
| `AI_PLATFORM_NOT_CONFIGURED` | 503 | the organization uses platform AI and no provider is set up | platform administrator (console, System > AI provider) |
| `AI_DISABLED` | 403 | AI triage is off for the organization (not turned on yet, or turned off) | organization administrator (Settings > AI) |
| `AI_OWN_PROVIDER_NOT_ALLOWED` | 403 | the organization uses (or tries to use) its own provider and the platform policy forbids it | platform administrator (console) or organization administrator (switch to Platform AI) |
| `AI_POLICY_RESTRICTED` | 403 | the AI data policy keeps this finding on the platform | campaign lead or organization administrator |

A failed triage stores a fixed failure code in `error_message`; the API
returns it as `error_code`, and the web UI translates it. Raw error text
(database, provider, network) is logged on the server only, never stored,
shown, broadcast, sent to workflows or written to the audit log. Rows from
before the codes read as `internal_error`.

Codes: `internal_error`, `ai_policy_restricted`, `ai_disabled`, `provider_not_configured`,
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

## Providers

`claude`, `openai`, `gemini` and `openai_compatible`. The last one speaks
the OpenAI chat-completions API at a base URL (`<base>/chat/completions`)
and a model name the administrator sets, so one adapter covers Azure
OpenAI's v1 endpoint, vLLM, Ollama, LM Studio, LiteLLM, OpenRouter and cloud
gateways. The API key is optional for it (a server inside the network may
not need one). The former `azure_openai` and `agent` modes are removed.

Every provider call uses the SSRF-safe HTTP client (`pkg/httpsec`): the host
is resolved once, every answer is vetted and the connection goes to the
vetted address, so DNS rebinding cannot redirect it. Redirects are not
followed, and a self-hosted server's error text is never relayed (only the
status).

- **Platform provider** (console, super admin, fresh step-up, reason, critical
  audit): the toggle "allow private addresses" lets the base URL be on a
  private network (RFC1918 and ULA ranges, plain http). Loopback, link-local
  and cloud-metadata addresses, carrier-grade NAT and `localhost` stay
  blocked, toggle or not. Changing the toggle is part of the audited change
  (`previous_allow_private`, `allow_private`). With the toggle off, a private
  address is refused when the setting is saved and again at every connection.
- **Organization's own provider** (`openai_compatible` base URL): public
  addresses and https only, never the toggle, so an organization cannot reach
  the platform's network. The URL is vetted when the provider is built and at
  every connection.
- **Model allow-list** (console): when set, the platform model must be one
  of the listed models.

## Own provider (bring your own)

Settings > AI has a **Source**: Platform AI, Own provider or Off. Off and
Platform need no more; Own provider takes a kind (`claude`, `openai`,
`gemini`, `openai_compatible`), a base URL and model (`openai_compatible`
only needs the URL; the model is required there), and an API key. The
whole thing is one table, `tenant_ai_settings` (one row per organization:
consent, source, provider, base URL, model, encrypted key, key last four
characters, who and when, the auto-triage policy as JSON). It replaces the
old `tenants.settings.ai` JSON (the `tenant_ai_settings` migration moved the data and removed
it).

`GET/PUT /api/v1/organization/settings/ai` and `POST .../test`:

- GET returns the settings and the key as `{set, last4, updated_at,
  updated_by}`; the key is never returned. Needs owner or administrator and
  `settings:read`.
- PUT is a partial change (consent, source, provider, base URL, model, key:
  omit to keep, `""` to remove). Needs owner or administrator,
  `settings:write` and a recent sign-in; audited as critical
  `ai_settings.updated` with before and after of everything except the key.
- POST `/test` calls the provider from the server with one tiny prompt ("Reply
  with OK."; no finding data), with the form's values over the stored ones, and
  answers `{ok, code}` with a fixed code (`ok`, `invalid_url`,
  `blocked_address`, `key_required`, `not_configured`, `auth_failed`,
  `rate_limited`, `timeout`, `unreachable`, `provider_error`), never the
  provider's text. Three tests in a burst, then one every five seconds per
  organization; audited as `ai_settings.tested` (low).

Rules that keep it safe:

- The key is encrypted with `APP_ENCRYPTION_KEY` (`tenant_ai_settings.key_enc`,
  in the rekey registry), write-only, and never in the audit log.
- A stored key is sent only to the endpoint it was entered for: changing the
  provider or the base URL drops it, and a test with another provider or URL
  needs the key entered again.
- The base URL is public https only (see Providers); the platform's private-address
  toggle never applies to an organization.
- The platform policy "allow organizations to use their own provider"
  (console, System > AI provider; super admin, fresh confirmation, reason,
  critical audit; on by default, stored as `ai.org_policy`) can forbid it.
  Selecting or testing an own provider then answers `403
  AI_OWN_PROVIDER_NOT_ALLOWED`; a job of an organization already on its own
  provider fails with `provider_not_configured` and never falls back to the
  platform key.
- Consent, the AI data-egress policy (TLP, campaign opt-out), the monthly cap
  and the per-organization rate bucket apply the same way whichever source
  pays; each result records the provider and the model.

## Keys

The console's platform provider key (`platform_settings` key `ai.platform`,
`key_encrypted`) and an organization's own key (`tenant_ai_settings.key_enc`)
are in the rekey registry, so rotating `APP_ENCRYPTION_KEY` with `rekey`
carries them over.

## Threat model

- Assets: finding and pentest content, keys, the platform's spend.
- Actors: a scanned target that plants text in HTTP bodies or code (prompt
  injection); a member burning the platform's budget; another organization;
  the provider (retention).
- Controls: organization consent (checked at request time and in the
  worker); nonce-fenced prompt and output validation; no automatic effect
  of a verdict; the AI data-egress policy at request time and in the worker;
  monthly budgets and per-organization fair share;
  data scope and pentest membership on the routes; tenant-scoped queries
  everywhere; every provider call through the SSRF-safe client, an
  organization's base URL public-only; encrypted,
  write-only keys in the rekey registry; failure codes instead of raw
  errors.

## Planned

Context enrichment and redaction with a "what was sent"
record, a structured result schema, the result card with apply actions and
history, "Triage selected" bulk on a fair-share queue with a result cache,
an atomic de-duplication index, and an evaluation set (RFC-119).

### Secret findings and the model provider

For a leaked-secret finding the code snippet is withheld, and the description is passed through the shared secret redactor (`safetext.RedactSecrets`) before it enters the prompt, so a credential quoted in the description never reaches the provider.
