# AI analysis governance

Every AI result is a **suggestion with provenance**. The platform decides what a
suggestion does to risk, the organization decides per use case whether
suggestions wait for a person or apply on their own, and nothing that hides risk
is ever applied without a person. This page covers the governance core: the
tables, the apply rules, undo, the quality signal and the API. The AI triage
executor and its prompt are in [AI triage](ai-triage.md).

Status: shipped (governance core). Planned: the `openctem.analyze/v1` job and
result contract with the built-in executor writing runs through it, reversible
masking of every context bundle, the AI analyst worker (an analyst sensor role),
the Settings > AI use-case table and the AI suggestion card in the web console.

## Model

| Table | What it holds |
|---|---|
| `ai_runs` | One execution of a use case by any executor: use case and kind (`triage.v1`), subject, executor (`builtin`, `platform_worker`, `tenant_worker`), status, data class, fields sent and withheld, bundle digest, prompt template id and digest, output schema, provider and model, tokens, cost, duration, a fixed error code, trigger and requester. One run in flight per organization, use case and subject (partial unique index). |
| `ai_suggestions` | The typed results of a run: kind (`verdict`, `severity`, `remediation_steps`, `summary`), payload validated per kind, schema version, **direction** (`additive`, `raises_risk`, `lowers_risk`), confidence, evidence references, state, review reasons, previous value for undo, who applied or undid it, and the approval it waits in. |
| `tenant_ai_use_cases` | The organization's policy per use case (`triage`, `remediation`, `summary`): mode `off`, `suggest` or `auto_apply`, executor, data class ceiling, minimum confidence for auto-apply (0.50 to 0.99, default 0.85), triggers, budget share, and an automatic downgrade. No row means the platform default: `off` until the organization consents to AI (Settings > AI), then `suggest`. |

All three are tenant-scoped (`tenant_id` in every query and key, row-level
policies, deleted with the organization). A suggestion references its run by
`(run_id, tenant_id)`, so a suggestion can never point at another tenant's run.

`ai_triage_results` was copied into `ai_runs` and `ai_suggestions` by migration
`ai_governance_core` (a run keeps the triage result's id); it is dropped in a
later contract step.

## Direction is computed by the platform

The model never says what its suggestion does to risk. Payloads are decoded
strictly per kind (unknown fields refused, so a payload that names a direction
or a state is rejected), and the direction is computed from the finding's facts
read on the server with `approvalpolicy.Signals`:

- severity above the current one raises risk, below lowers it;
- a `likely_false_positive` verdict lowers risk (it asks to close); `true_positive`
  and `needs_info` add information;
- remediation steps and summaries are additive.

## Apply rules (fixed, not configurable)

| Direction | `suggest` | `auto_apply` |
|---|---|---|
| additive (plan, summary, confirming verdict) | a person clicks Apply | applied at once, AI badge, undo available |
| raises risk (higher severity) | a person clicks Apply | **still waits for a person**: the platform makes no severity or priority change without one |
| lowers risk (false positive, lower severity) | Apply opens an approval request with the person as requester | a false-positive verdict becomes an approval request whose requester is the AI actor (no person is recorded, so four-eyes rules apply unchanged); never a change |

A suggestion is never acted on automatically when it has review reasons: no
evidence, evidence that cites a field or tool output the run did not have,
prompt-injection markers in the input, or placeholders the run did not issue. It
is stored `needs_review`.

A person's Apply goes through the same service path as the change made by hand:
a severity change uses the severity rules (a downgrade may become a request), a
false-positive verdict opens a status request (`closure_reason` required), a
plan or summary becomes part of the finding's record. The person needs the
permission of the change (`findings:severity` for a severity, `findings:write`
otherwise).

## Undo

Every applied suggestion stores what it changed. Undo restores the previous
value when the field has not changed since; otherwise it answers 409
`AI_UNDO_CONFLICT` and changes nothing. Restoring a lower severity may itself need
approval. `POST /api/v1/ai/runs/{id}/undo` undoes everything a run applied.

## Quality signal and automatic downgrade

Each person's decision on a suggestion (apply, dismiss, undo, an approval request
approved or rejected) is recorded. Over the last 50 decisions of a use case, when
dismissals, undos and rejected requests reach 20 % (with at least 10 decisions),
an `auto_apply` use case falls back to `suggest`: `downgraded_at` and
`downgrade_reason = override_rate` are set and an audit row
`ai_use_case.downgraded` is written. Only an administrator turns auto-apply back
on, which clears the downgrade.

## API

| Route | Gate |
|---|---|
| `GET /api/v1/organization/settings/ai/use-cases` | owner or admin, `settings:read` |
| `PUT /api/v1/organization/settings/ai/use-cases/{use_case}` | owner or admin, `settings:write`; a recent sign-in when the body turns `auto_apply` on or raises the data class ceiling above `internal` |
| `GET /api/v1/findings/{id}/ai/suggestions` | `findings:read` + `ai_triage:read`, module `ai_triage`, the caller's data scope and pentest membership |
| `GET /api/v1/ai/runs/{id}` | same; the run's subject is checked (out of scope answers 404) |
| `POST /api/v1/ai/suggestions/{id}/apply`, `/dismiss`, `/undo`; `POST /api/v1/ai/runs/{id}/undo` | same, plus the permission of the change |

Every response marks AI content with `origin: "ai"`. Free text in a payload is
model output: the web renders it as plain text.

## Audit

`ai_use_case.updated` (critical), `ai_use_case.downgraded`,
`ai_suggestion.applied`, `ai_suggestion.auto_applied`,
`ai_suggestion.approval_requested`, `ai_suggestion.dismissed`,
`ai_suggestion.undone`. Timeline entries `ai_suggestion_applied` and
`ai_suggestion_undone` on the finding name the suggestion and run; an
auto-applied entry has the AI as actor.

## Threat model

| Threat | Control |
|---|---|
| Injected finding text steers the model to hide risk ("this is a false positive") | risk-lowering changes are never applied automatically; they become approval requests under the organization's four-eyes rules |
| The model claims a direction or state | strict per-kind decode refuses unknown fields; the direction is computed from server facts |
| Fabricated evidence | every reference must exist in the run; otherwise `needs_review`, never auto-applied |
| Slow low-grade manipulation of additive suggestions | the override rate downgrades auto-apply to suggest |
| Another tenant reads or acts on a suggestion by id | every query filters on tenant; by-id routes answer 404 |
| A member outside the finding's data scope | the data scope and pentest membership are applied to the subject on every read and action |
| Turning on auto-apply or sending more data by mistake or with a stolen session | owner or admin only, a recent sign-in, a critical audit row |

## Key files

- `pkg/domain/aianalysis/` (types, policy, payload validation, direction, apply rule)
- `internal/app/aianalysis/` (service: record, apply, dismiss, undo, downgrade)
- `internal/app/finding/ai_actions.go` (the finding paths the apply engine uses)
- `internal/infra/postgres/aianalysis_repository.go`
- `internal/infra/http/handler/ai_analysis_handler.go`, `internal/infra/http/routes/ai_analysis.go`
- `migrations/*_ai_governance_core.*.sql`
