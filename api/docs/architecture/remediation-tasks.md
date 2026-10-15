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
  `resolution_method` `scan_verified`, `retest_verified` or `security_reviewed`.
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

## Shipped and planned

Shipped: everything above. Planned (RFC-098 §5–§8): suggestions and accept flows, auto-join, moves, split,
merge and detach, task-level mark fixed and regression tasks, the new Remediation console.

## Key files

- `api/migrations/002290_remediation_tasks.up.sql`, `002291`/`002292` (finding activity type)
- `api/pkg/domain/remediation/task.go`, `task_repository.go`
- `api/internal/infra/postgres/remediation_task_repository.go`
- `api/internal/app/remediation/tasks.go`
- `api/internal/infra/http/handler/remediation_task_handler.go`, `routes/remediation.go`
- `api/internal/infra/controller/remediation_tasks.go`
- `api/tests/integration/remediation_tasks_test.go`
