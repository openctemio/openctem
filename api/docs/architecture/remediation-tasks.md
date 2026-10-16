# Remediation tasks

Design: [RFC-098](../rfcs/RFC-098-remediation-tasks.md). This page describes what is shipped and how it works.

## What it is

A remediation task groups the findings one fix closes and gives them one owner and one deadline. Its state is
derived from the findings; a person sets only the title, the owner, a tighter deadline, the campaign and the
manual states (on hold, canceled).

| Concept | Table | Notes |
|---|---|---|
| Action (what fixes it) | `remediation_actions` | one per key and tenant; a hand-made task gets `manual:<task id>` |
| Task (who, by when) | `remediation_tasks` | owner user and/or group, derived `state`, `deadline`, counters, `risk_points`, `version` |
| Membership | `remediation_task_members` | `primary` (one active task per finding) or `related`; history kept with `left_at` |
| Timeline | `remediation_task_events` | created, members added, updated, state changed |

## State and deadline

- States: `open`, `in_progress`, `verifying`, `done`, `closed_unverified`, `on_hold`, `canceled`, `archived`
  (rules in RFC-098 §3). `done` needs every finding closed and at least one verified fixed: resolved with
  `closure_reason` `fixed` and `verification` `covered_scan`, `retest` or `security_review`.
- `deadline` is the earliest of the open findings' `sla_deadline`, the task's `manual_deadline` and its
  campaign's due date (end of that day, UTC), so a manual or campaign deadline only tightens.
- `risk_points` sums the open findings' weights (P0 8, P1 4, P2 2, P3 1; unclassified: critical 4, high 2,
  medium and low 1).
- Recompute runs in the transaction of every change (create, add members, update) and in the
  `remediation-tasks` controller every two minutes for tasks whose findings changed since `recomputed_at`
  (`StaleTasksForPlatform`, oldest first, 500 per pass). A state change is written to the timeline.

## Membership rules

- Creating a task or adding primary members refuses a finding that is already the primary member of another
  active task: `409` with `code: FINDINGS_IN_OTHER_TASK` and the `finding_ids`.
- Closed findings never join as primary members; another tenant's finding, a missing one and one outside the
  caller's scope answer the same `404`.
- Canceling a task (a reason is required) releases its findings (`left_reason = canceled`), so they may join
  another task. Terminal tasks (`done`, `closed_unverified`, `canceled`, `archived`) take no edits and no new
  members.
- Every join and leave writes a `remediation_task_changed` activity on the finding.

## API

| Route | Gate |
|---|---|
| `GET /api/v1/remediation/tasks` | `findings:remediation:read` |
| `POST /api/v1/remediation/tasks` | `findings:remediation:write` |
| `GET /api/v1/remediation/tasks/{task_id}` | `findings:remediation:read` |
| `PATCH /api/v1/remediation/tasks/{task_id}` | `findings:remediation:write` |
| `GET /api/v1/remediation/tasks/{task_id}/members` | `findings:remediation:read` + `findings:read` |
| `POST /api/v1/remediation/tasks/{task_id}/members` | `findings:remediation:write` |
| `GET /api/v1/remediation/tasks/{task_id}/timeline` | `findings:remediation:read` |

All routes are in the `remediation` module. `assignee=me` lists tasks assigned to the caller or to one of their
groups. Every change carries the task's `version`; a stale one answers `409`.

## Data scope

A restricted member sees a task through its findings in their scope: counters, deadline and risk are over those
findings and `hidden_members` counts the others. A task with none of their findings is `404`. They may change a
task only when `hidden_members` is 0, and every finding they name must be in their scope.

## Suggestions

The generator only proposes; nothing is created until a person accepts.

- **Candidates:** open, non-pentest findings with a remediation key (`finding_remediation_keys`) that are not
  the primary member of an active task and not excluded for that key (`remediation_key_exclusions`).
- **Owner:** the asset's first primary user owner (an active member) and first primary group owner
  (`asset_owners`); none = the default queue.
- **Kinds:** a key with no action → one `new_group` suggestion with a partition per owner (at least two
  findings unless one is P0 or in KEV); a key with an action → per owner, `join` into that owner's live task or
  `task_route` for a new task.
- **Rank:** risk points, then findings, then the earliest SLA deadline. Confidence: 1.0 for `upgrade` and
  `rotate` keys, 0.7 for `sol` (solution text) keys.
- **Lifecycle:** `proposed`, `snoozed` (wakes at its date), `dismissed` (reason required; proposed again only
  when findings grow by half or by ten, risk doubles or a finding becomes P0/KEV), `expired` (the run no longer
  produces it), `accepted`.
- **Noise:** at most 50 new suggestions shown per tenant per 24 hours (the rest wait, `queued` in the list and
  stats); one `remediation_suggestions_digest` notification per tenant per day when new ones were shown.
- **Runs:** the `remediation-suggestions` controller every 15 minutes (tenants with the remediation module on),
  and `POST /api/v1/remediation/suggestions/run` (once a minute per tenant). One run = one transaction under a
  per-tenant advisory lock.

| Route | Gate |
|---|---|
| `GET /api/v1/remediation/suggestions`, `/stats`, `/{id}` | `findings:remediation:read` |
| `GET /api/v1/remediation/suggestions/{id}/members` | `findings:remediation:read` + `findings:read` |
| `POST /run`, `PATCH /{id}` (snooze), `POST /{id}/reject`, `POST /{id}/reopen` | `findings:remediation:write` |

A restricted member sees a suggestion through its in-scope findings only (no ids of the others,
`hidden_members` counts them) and may not decide on one with hidden findings.

## Accepting suggestions

- `POST /api/v1/remediation/suggestions/{id}/approve` (`findings:remediation:write`), at the suggestion's
  `version`: `new_group` creates the action (`origin = suggestion`) and one task per partition owner;
  `task_route` creates a task under the existing action; `join` adds the findings to the target task (the caller
  must see all of that task's findings). Edits: `title`, `exclude_finding_ids` (remembered in
  `remediation_key_exclusions`), `owners` per partition index, `deadline`, `auto_join`.
- Findings that closed or joined another task since the suggestion are left out and returned in `dropped`; with
  none left the accept answers 400.
- `POST /api/v1/remediation/suggestions/approve` accepts up to 50 suggestions (5000 findings) as they are, each
  on its own.
- Auto-join (`remediation_actions.auto_join`, `PATCH /api/v1/remediation/actions/{id}`): exact keys only
  (`upgrade`, `rotate`); needs a caller with no data-scope restriction. Each generator run first adds new
  findings of such a key to the owner's `open` or `in_progress` task (join source `auto_join`, at most 200 per
  action per day); a `verifying`, held or closed task gets a `join` suggestion instead. It never changes a
  finding's status.

## Shipped and planned

Shipped: everything above. Planned (RFC-098 §7–§8): moves, split, merge and detach, task-level mark fixed and
regression tasks, the new Remediation console.

## Key files

- `api/migrations/*_remediation_tasks.up.sql`, `*_remediation_task_activity_type*.sql` (finding activity type)
- `api/pkg/domain/remediation/task.go`, `task_repository.go`
- `api/internal/infra/postgres/remediation_task_repository.go`
- `api/internal/app/remediation/tasks.go`
- `api/internal/infra/http/handler/remediation_task_handler.go`, `routes/remediation.go`
- `api/internal/infra/controller/remediation_tasks.go`
- `api/migrations/*_remediation_suggestions.up.sql`
- `api/pkg/domain/remediation/suggestion.go` (generator rules), `api/internal/app/remediation/suggestions.go`,
  `api/internal/infra/postgres/remediation_suggestion_repository.go`,
  `api/internal/infra/http/handler/remediation_suggestion_handler.go`,
  `api/internal/infra/controller/remediation_suggestions.go`
- `api/tests/integration/remediation_tasks_test.go`, `remediation_suggestions_test.go`
