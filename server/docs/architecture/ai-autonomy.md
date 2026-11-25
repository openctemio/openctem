# Changes AI agents make without a person

Code: `pkg/domain/aianalysis/autonomy.go`, `internal/app/tenantai/autonomy.go`,
`internal/infra/postgres/tenant_ai_autonomy.go`, `internal/infra/http/handler/ai_autonomy_handler.go`,
enforcement in `internal/app/aianalysis/builtin.go` (`AutonomyGate`), migration `ai_worker_results`.
Related: [AI agents](ai-analysis.md), [AI use cases](ai-use-cases.md).

An AI agent changes a finding without a person in one case only: a `true_positive` verdict moves a
`new` finding to `confirmed`, when the triage use case is on auto-apply at or above its minimum
confidence. Anything that lowers risk (false positive, a lower severity, duplicate, risk acceptance,
closing) is a request a person decides, whatever the settings. On top of the use case setting, the
organization has one switch and two limits for those changes.

## The setting

| Field | Values | Default |
|---|---|---|
| `paused` | `true` stops every change without a person at once | `false` |
| `per_hour` | changes without a person in the current clock hour (UTC): 0 to 100,000, or `null` for unlimited | 100 |
| `per_day` | changes without a person in the last 24 clock hours: 0 to 100,000, or `null` for unlimited | 500 |

Stored in `tenant_ai_settings.autonomy` (JSON, `version: 1`); `NULL` reads as the defaults. A limit of
0 holds every change, like a pause.

## How it applies

- The executors ask (`AllowAutomaticChange`) at the moment they would change the finding, for the
  built-in executor and for AI worker results alike, so a pause applies at once to runs already in
  flight.
- A held change is written as the AI agent's comment for a person, with the reason
  (`autonomy_paused`, `limit_reached`) in the run's action log; the run's outcome is `proposed`.
- Each allowed change is counted in `ai_auto_change_counts` (organization, clock hour). The count and
  the check run under a transaction-scoped advisory lock on the organization, so concurrent runs
  cannot both take the last slot. Counts older than two days are dropped as new ones are written.
- An unreadable setting or count holds the change (fail closed).

## API

| Route | Gate |
|---|---|
| `GET /api/v1/organization/settings/ai/autonomy` | `settings:read` |
| `PUT /api/v1/organization/settings/ai/autonomy` | owner or administrator with `settings:write`; a loosening needs a recent sign-in |

`PUT` takes `{"paused": bool, "per_hour": int|null, "per_day": int|null}`; both limits are required
(`null` is unlimited, so a missing field never means "unlimited").

- Pausing and lowering a limit need no recent sign-in: one click in an incident. Audited
  `ai_autonomy.paused` (high) and `ai_autonomy.updated` (medium).
- Resuming, raising a limit or making it unlimited is a loosening: a recent sign-in
  (`403 STEP_UP_REQUIRED` otherwise), audited `ai_autonomy.resumed` / `ai_autonomy.updated` as
  critical, and every owner and administrator is told.
- The tenant is the token's; another organization's setting is never read or written.

## Tests

`internal/infra/http/routes/ai_autonomy_route_db_test.go`: defaults, the authorization matrix, both
limits required and bounded, pause and lower without a recent sign-in, resume / raise / remove refused
on a stale sign-in and nothing stored, audit severities, tenant isolation.
`internal/infra/http/routes/ai_worker_result_db_test.go` (`TestAIWorkerResult_OrganizationPauseAndLimits_DB`):
a pause set while a job was out holds its confirm; with one change an hour the first applies and the
second is held.

## Planned

Trust earned per class of finding, a check sample of automatic changes, undo and the platform-wide
switch are designed (finding review states and earned autonomy) and not built.
