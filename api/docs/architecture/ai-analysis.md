# AI analysts

Design: [RFC-132](../rfcs/RFC-132-ai-analyst-principal.md). Code: `pkg/domain/aianalysis`,
`internal/app/aianalysis`, `internal/infra/postgres/aianalysis_repository.go`,
`internal/infra/http/handler/ai_analysis_handler.go`, migration `ai_analysts`.

An **AI analyst** takes part in triage like a person. It calls the same commands, with its own preset
and data scope, and its changes go through the same approvals, audit and notifications. The only
differences are the AI label and the provenance on everything it does.

## Identity

- An analyst is a **service account** (`users.kind = 'service'`) plus one row in `ai_analysts`.
  The service-account triggers apply unchanged: one organization only, never owner or administrator,
  never full data access, never a sign-in identity (no password, no MFA, no session).
- It is **not a seat**: the seat count skips service accounts that have an `ai_analysts` row
  (`LimitsRepository.Usage`).
- It is **never an approver**: the approver directory lists people only
  (`ScopeActorRepository.FindingApprovers`), and an analyst never holds an approve permission
  (deny list below).
- It has **no credential and no role of its own**: triggers refuse an API key, an MCP grant or a
  `user_roles` row for an analyst, and a service account that has any of those cannot become one.
  The service-account screens refuse to mint its keys or delete it. It acts only through the
  platform's executor, which resolves it at every run (owners, attestation, preset, deny list).
- Several analysts per organization are allowed, for example one per team with that team's asset
  scope.

## What an analyst may do

Effective permissions are computed at every run start (`Service.Principal`), fail closed:

```
effective = preset permissions
            ∩ union of what the accountable people hold (an owner or administrator holds everything)
            − deny list
```

- **Preset** (in code, `aianalysis.Preset.Permissions`; no editable role, so nobody widens an analyst
  by editing a role). The person who sets a preset must hold its permissions:
  - `suggest`: read, comment, open approval requests.
  - `triage`: also status, triage (duplicates), severity, assignment.
- **Deny list** (`aianalysis.Denied`): every `*:approve`, `*:delete`, `*:export` and `*:reveal`,
  `findings:verify`, `findings:fix_apply`, `findings:bulk_update`, lifecycle and retest-check
  writes, and everything under `settings:`, `team:`, `integrations:`, `audit:`, `sensors:`,
  `service_accounts:`, `findings:suppressions:` and `scans:` (except `scans:read`).
- **Ceiling**: setting a preset or changing owners is refused when the preset carries a
  permission no accountable person holds (the error names it). At run start the analyst gets
  the intersection, so it loses a permission the moment its owners do.
- **Data scope**: the analyst's own team memberships. A subject must also be visible to at least one
  accountable person (`Principal.AssertFinding`); out of scope reads as not found.

Risk-lowering changes always become requests. When the requester is an analyst, the finding service
evaluates the request at the strictest false-positive and acceptance level and treats the requester
as unable to approve, whatever the organization's settings (`VulnerabilityService.isAIAnalyst` in
`finding/approval_policy.go`), so a person always decides.

## Accountable owners

`ai_analyst_owners` holds people and teams (at least one). The **accountable people** are the person
owners who are active members and the active person members of active owner teams, with membership
end dates honoured (`AnalystRepository.PeopleOf`).

| Event | Effect |
|---|---|
| No accountable person left (offboarding, suspension, team emptied or deactivated) | the analyst pauses with `no_active_owner` at the next run start and at the hourly sweep (`AIAnalystSweepController`) |
| Attestation older than 90 days (`attest_due_at`) | pauses with `attestation_expired`; an owner (or an administrator) attests to resume |
| Nothing effective left | pauses with `no_permissions` |
| Owners replaced | needs `service_accounts:manage` and a recent sign-in; the preset must fit the new owners; a `no_active_owner` pause lifts |

Owners may pause their analyst. `service_accounts:manage` disables it (kill switch) and, with a recent
sign-in, resumes, deletes or changes it. Every change is a critical or high audit row
(`ai_analyst.*`).

## Provenance

The executor puts an `aianalysis.Provenance` in the context before it calls any command: analyst,
run, executor, provider, model, prompt template id and digest, the accountable owners at that moment,
and who triggered the run.

- The finding activity writer stamps `source = 'ai_analyst'` and `source_metadata.ai` on rows the
  analyst writes; a database trigger labels **every** row whose actor is an analyst
  `actor_type = 'ai'`, whatever code path wrote it.
- The audit logger stamps `metadata.ai` and `auth_method = 'ai_analyst'`.
- Rows whose actor is someone else in the same context are not stamped.
- An expression index on `source_metadata->'ai'->>'run_id'` serves per-run queries (undo, metrics).

## Runs

`ai_runs` is the ledger: one row per run with the analyst, the accountable snapshot, the trigger and
who triggered it, model and prompt, bundle digest, fields sent and withheld, usage and cost. Status is
the run's logical state: `queued`, `running`, `waiting_tool`, `waiting_approval`, then `completed`,
`failed`, `canceled` or `refused`.

- One live run per subject and use case (partial unique index). A live run past its deadline
  (`RunDeadline`) gives the slot up when the next run starts (failed with `timeout`).
- Budgets per analyst: runs per hour, tokens per month (inside the organization's AI token budget).
- A run is readable only by someone who can see its subject (finding subjects only for now).
- The per-run index on `finding_activities` is built concurrently by its own migration.

## API

| Route | Gate |
|---|---|
| `GET /api/v1/ai/analysts`, `GET /api/v1/ai/analysts/{id}` | `ai_triage:read` |
| `POST /api/v1/ai/analysts`, `DELETE /{id}`, `PUT /{id}/owners`, `PUT /{id}/preset`, `POST /{id}/resume` | `service_accounts:manage` + recent sign-in |
| `POST /api/v1/ai/analysts/{id}/disable` | `service_accounts:manage` |
| `POST /api/v1/ai/analysts/{id}/pause` | `ai_triage:read`; an accountable person or `service_accounts:manage` |
| `POST /api/v1/ai/analysts/{id}/attest` | `ai_triage:read` + recent sign-in; an accountable person or an administrator |
| `GET /api/v1/ai/runs/{id}`, `GET /api/v1/findings/{id}/ai/runs` | `findings:read` + `ai_triage:read`; the subject in the caller's scope |

## Tests

`internal/infra/http/routes/ai_analyst_db_test.go` (real Postgres): no API key, MCP grant, role,
identity or password for an analyst; risk-lowering waits for a person with the organization's
approval levels off; service account within its preset,
ceiling at create and at run start, never an approver, cross-tenant refusals, own plus owner data
scope, pause when the owner leaves and when a team empties (sweep), attestation expiry, kill switch,
one live run under a race of eight workers, activity label and provenance, not a seat.
`pkg/domain/aianalysis/analyst_test.go`: deny list, ceiling, presets, health, provenance stamping,
analyst requests always need a person.
