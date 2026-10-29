# AI agents

Design: [RFC-132](../rfcs/RFC-132-ai-agent-principal.md). Code: `pkg/domain/aianalysis`,
`internal/app/aianalysis`, `internal/infra/postgres/aianalysis_repository.go`,
`internal/infra/http/handler/ai_analysis_handler.go`, migration `ai_agents`.

An **AI agent** takes part in triage like a person. It calls the same commands, with its own preset
and data scope, and its changes go through the same approvals, audit and notifications. The only
differences are the AI label and the provenance on everything it does.

## Identity

- An AI agent is a **service account** (`users.kind = 'service'`) plus one row in `ai_agents`.
  The service-account triggers apply unchanged: one organization only, never owner or administrator,
  never full data access, never a sign-in identity (no password, no MFA, no session).
- It is **not a seat**: the seat count skips service accounts that have an `ai_agents` row
  (`LimitsRepository.Usage`).
- It is **never an approver**: the approver directory lists people only
  (`ScopeActorRepository.FindingApprovers`), and an AI agent never holds an approve permission
  (deny list below).
- It has a **role** (`ai_agents.role`: `analyst` by default, `remediator`, `reporter`, `hunter`, `router`) that
  says what it is for. The role grants nothing; the preset below sets what it may do. Only the analyst role
  has a built-in executor today.
- It has **no credential and no database role of its own**: triggers refuse an API key, an MCP grant or a
  `user_roles` row for an AI agent, and a service account that has any of those cannot become one.
  The service-account screens refuse to mint its keys or delete it. It acts only through the
  platform's executor, which resolves it at every run (owners, attestation, preset, deny list).
- Several AI agents per organization are allowed, for example one per team with that team's asset
  scope.

## What an AI agent may do

Effective permissions are computed at every run start (`Service.Principal`), fail closed:

```
effective = preset permissions
            ∩ union of what the accountable people hold (an owner or administrator holds everything)
            − deny list
```

- **Preset** (in code, `aianalysis.Preset.Permissions`; no editable role, so nobody widens an AI agent
  by editing a role). The person who sets a preset must hold its permissions:
  - `suggest`: read, comment, open approval requests.
  - `triage`: also status, triage (duplicates), severity, assignment.
- **Deny list** (`aianalysis.Denied`): every `*:approve`, `*:delete`, `*:export` and `*:reveal`,
  `findings:verify`, `findings:fix_apply`, `findings:bulk_update`, lifecycle and retest-check
  writes, and everything under `settings:`, `team:`, `integrations:`, `audit:`, `sensors:`,
  `service_accounts:`, `findings:suppressions:` and `scans:` (except `scans:read`).
- **Ceiling**: setting a preset or changing owners is refused when the preset carries a
  permission no accountable person holds (the error names it). At run start the AI agent gets
  the intersection, so it loses a permission the moment its owners do.
- **Data scope**: the AI agent's own team memberships. A subject must also be visible to at least one
  accountable person (`Principal.AssertFinding`); out of scope reads as not found.

Risk-lowering changes always become requests. When the requester is an AI agent, the finding service
evaluates the request at the strictest false-positive and acceptance level and treats the requester
as unable to approve, whatever the organization's settings (`VulnerabilityService.isAIAgent` in
`finding/approval_policy.go`), so a person always decides.

## Read-only assistance

Help that changes nothing (explain a finding, summarize a timeline, translate, answer a question) runs
under the viewer's own permissions and has no AI agent principal. It runs in an assistance context
(`aianalysis.WithAssist`), set only in process (no token or header sets it). In that context:

- every finding write path refuses with `ErrAssistReadOnly` (`aianalysis.RefuseAssist`: finding
  create and update, status batches, severity decisions, comments, approval and severity requests,
  retest requests, timeline rows);
- `postgres.DB` refuses `ExecContext`, a non-read-only `BeginTx` and any writing statement through
  `QueryContext`/`QueryRowContext`;
- `Service.Principal` and `Service.StartRun` refuse, so assistance can never act as an AI agent.

A comment drafted with AI is posted by the viewer, as themselves, outside the assistance context.
Every change to state is made by an AI agent.

## Accountable owners

`ai_agent_owners` holds people and teams (at least one). The **accountable people** are the person
owners who are active members and the active person members of active owner teams, with membership
end dates honoured (`AgentRepository.PeopleOf`).

| Event | Effect |
|---|---|
| No accountable person left (offboarding, suspension, team emptied or deactivated) | the AI agent pauses with `no_active_owner` at the next run start and at the hourly sweep (`AIAgentSweepController`) |
| Attestation older than 90 days (`attest_due_at`) | pauses with `attestation_expired`; an owner (or an administrator) attests to resume |
| Nothing effective left | pauses with `no_permissions` |
| Owners replaced | needs `service_accounts:manage` and a recent sign-in; the preset must fit the new owners; a `no_active_owner` pause lifts |

Owners may pause their AI agent. `service_accounts:manage` disables it (kill switch) and, with a recent
sign-in, resumes, deletes or changes it. Every change is a critical or high audit row
(`ai_agent.*`).

## Provenance

The executor puts an `aianalysis.Provenance` in the context before it calls any command: AI agent,
run, executor, provider, model, prompt template id and digest, the accountable owners at that moment,
and who triggered the run.

- The finding activity writer stamps `source = 'ai_agent'` and `source_metadata.ai` on rows the
  AI agent writes; a database trigger labels **every** row whose actor is an AI agent
  `actor_type = 'ai'`, whatever code path wrote it.
- The audit logger stamps `metadata.ai` and `auth_method = 'ai_agent'`.
- Rows whose actor is someone else in the same context are not stamped.
- An expression index on `source_metadata->'ai'->>'run_id'` serves per-run queries (undo, metrics).

## Runs

`ai_runs` is the ledger: one row per run with the AI agent, the accountable snapshot, the trigger and
who triggered it, model and prompt, bundle digest, fields sent and withheld, usage and cost. Status is
the run's logical state: `queued`, `running`, `waiting_tool`, `waiting_approval`, then `completed`,
`failed`, `canceled` or `refused`.

- One live run per subject and use case (partial unique index). A live run past its deadline
  (`RunDeadline`) gives the slot up when the next run starts (failed with `timeout`).
- Budgets per AI agent: runs per hour, tokens per month (inside the organization's AI token budget).
- A run is readable only by someone who can see its subject (finding subjects only for now).
- The per-run index on `finding_activities` is built concurrently by its own migration.

## API

| Route | Gate |
|---|---|
| `GET /api/v1/ai/agents`, `GET /api/v1/ai/agents/{id}` | `ai_triage:read` |
| `POST /api/v1/ai/agents`, `DELETE /{id}`, `PUT /{id}/owners`, `PUT /{id}/preset`, `POST /{id}/reactivate` | `service_accounts:manage` + recent sign-in |
| `POST /api/v1/ai/agents/{id}/disable` | `service_accounts:manage` |
| `POST /api/v1/ai/agents/{id}/suspend` | `ai_triage:read`; an accountable person or `service_accounts:manage` |
| `POST /api/v1/ai/agents/{id}/attest` | `ai_triage:read` + recent sign-in; an accountable person or an administrator |
| `GET /api/v1/ai/runs/{id}`, `GET /api/v1/findings/{id}/ai/runs` | `findings:read` + `ai_triage:read`; the subject in the caller's scope |

## Tests

`internal/infra/http/routes/ai_agent_db_test.go` (real Postgres): no API key, MCP grant, role,
identity or password for an AI agent; risk-lowering waits for a person with the organization's
approval levels off; service account within its preset,
ceiling at create and at run start, never an approver, cross-tenant refusals, own plus owner data
scope, pause when the owner leaves and when a team empties (sweep), attestation expiry, kill switch,
one live run under a race of eight workers, activity label and provenance, not a seat.
`TestAIAssist_CannotWrite_DB`: in an assistance context comment, status, severity and approval
request are refused and nothing is written; no principal is resolved.
`pkg/domain/aianalysis/agent_test.go`: deny list, ceiling, presets, health, provenance stamping,
AI agent requests always need a person.
