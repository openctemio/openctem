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

- Creating a task, adding primary members and accepting a suggestion claim their findings (RFC-098 §6.1,
  `claimFindingsInTx` in `remediation_claim.go`). A finding that is already the primary member of another
  active task refuses the request: `409` with `code: FINDINGS_IN_OTHER_TASK` and `details.conflicts`, one entry
  per finding (`finding_id`, `finding_title`, `task_id`, and `task_title`, `assignee_user_id`,
  `assignee_group_id` only when the caller can read that task, else null; `can_move`).
- The request resolves conflicts with `"conflicts": {"skip": true}` (leave them out) or
  `{"move": [ids], "move_reason": "..."}` (move those, skip the others). Moving needs write access to the
  holding task (visible, no finding outside the caller's scope; else `403`), ends the old membership with
  `left_reason = 'moved'`, keeps the SLA, writes timeline entries on both tasks, recomputes (and, when emptied,
  archives) the source, tells both trackers and writes one `remediation_task.findings_moved` audit row per source
  task. Of two concurrent claims of one finding exactly one wins; the other answers `409`.
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
| `POST /api/v1/remediation/tasks/query/preview`, `POST /api/v1/remediation/tasks/query` | `findings:remediation:write` + `findings:read`, query rate limit |
| `GET /api/v1/remediation/tasks/{task_id}/query` | `findings:remediation:read` |
| `POST /api/v1/remediation/tasks/{task_id}/query/{run,preview}` | `findings:remediation:write` + `findings:read`, query rate limit |
| `POST /api/v1/remediation/tasks/{task_id}/query/auto` | `findings:remediation:write` |

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
- Asset owners without `findings:remediation:write` reach the same route with `findings:remediation:read` and
  accept as the owner (`AcceptInput.AsOwner`, `owner_accept.go`): only a `join` into a task assigned to them or
  to one of their groups, or a `task_route` whose every partition owner is them or one of their groups; only as
  it is (no title, removed findings, owners, deadline or auto-join, since removed findings are remembered for
  everyone); every finding in their data scope (no hidden members) and on an asset they own as primary or
  secondary owner, directly or through a group (`asset_owners`, joined through `assets.tenant_id`). A new fix
  (`new_group`) stays with `findings:remediation:write`. The audit event carries `as_owner`. Owning an asset is
  not a scope grant: the data scope check applies on top.
- Findings that closed since the suggestion are left out and returned in `dropped`; findings another active task
  took since answer `409 FINDINGS_IN_OTHER_TASK` unless `conflicts` skips them (returned in `skipped`) or moves
  them (counted in `moved`); with none left the accept answers 400.
- `POST /api/v1/remediation/suggestions/approve` accepts up to 50 suggestions (5000 findings) as they are, each
  on its own.
- Auto-join (`remediation_actions.auto_join`, `PATCH /api/v1/remediation/actions/{id}`): exact keys only
  (`upgrade`, `rotate`); needs a caller with no data-scope restriction. Each generator run first adds new
  findings of such a key to the owner's `open` or `in_progress` task (join source `auto_join`, at most 200 per
  action per day); a `verifying`, held or closed task gets a `join` suggestion instead. It never changes a
  finding's status.

## Moves, split, merge, detach

| Route | Gate | Does |
|---|---|---|
| `POST /api/v1/remediation/moves/preview` | `findings:remediation:write` | the warnings of a move, nothing changes |
| `POST /api/v1/remediation/moves` | `findings:remediation:write` | moves findings (`confirm` for warnings; no target = detach) |
| `POST /api/v1/remediation/tasks/{task_id}/splits` | `findings:remediation:write` | new task of the same fix from some findings |
| `POST /api/v1/remediation/tasks/{task_id}/merges` | `findings:remediation:write` | moves all findings of same-fix tasks here |

- Refused: another tenant (404), a terminal task on either side, a task with findings outside the caller's
  scope, a finding outside it. Warned (409 `MOVE_NEEDS_CONFIRMATION` until `confirm`): different fix, different
  owner, target or source verifying, emptying the source.
- One transaction: both tasks locked in id order at the caller's versions, findings locked in id order, both
  sides recomputed; an emptied source is archived with a note naming the target; one timeline entry per task and
  a `remediation_task_changed` entry on every finding (left and joined). Findings not in the source are skipped
  and reported. A detach records `remediation_key_exclusions` (reason `detached`) for the source's key.
- Undo = the reverse move with the versions the response returns.
- Tracker comments: after the move is stored, `TaskService` calls `TaskMoveNotifier.TaskMembersMoved` (set with
  `SetMoveNotifier`; `internal/app/remediation/move_notify.go`) once per move, split, detach and once per merge
  source, with a `TaskMoveEvent`. `Comments()` (`pkg/domain/remediation/move.go`) words one comment per task
  touched from counts and task titles only. The task ticket integration implements the notifier for tasks with
  an active issue; it must not block the request and logs its own failures. Not wired in `cmd/server` until then
  (listed in the wiring guard's optional setters with that reason).

## Mark fixed and regressions

- `POST /api/v1/remediation/tasks/{task_id}/resolve` (`findings:remediation:write` + `findings:fix_apply`),
  body `version`, `note`: every open finding of the task goes to `fix_applied` through the finding bulk path
  (`WalkToFixApplied`: new/confirmed walk through in_progress; the asset owner's claim only; the bulk abuse
  guard; a proof-of-fix re-check queued per finding). The response lists each finding not updated with the
  reason; the task records a `fix_claimed` timeline entry. Nothing closes: each finding closes on its own
  evidence.
- A finding of a `done` or `closed_unverified` task that reopens is moved, at the next recompute, into a new
  task `Regression: <title>` with the same fix, owner, campaign and manual deadline and `regression_of` set;
  the closed task keeps its state (`regressed` timeline entry) and its history.

## Exception on a task (group exception)

"No maintenance window until 1 December" is one decision about the task's open findings (RFC-111 §7,
`internal/app/remediation/exception.go`, `internal/app/finding/approval_batch.go`,
`internal/infra/postgres/approval_batch_repository.go`):

- `POST /api/v1/remediation/tasks/{task_id}/exception/preview` and `POST .../exception`
  (`findings:remediation:write` + `findings:write`; every finding of the task in the caller's scope, as for any
  change of the task), body `requested_status` (`accepted` or `false_positive`), `closure_reason`,
  `justification` (the note), `expires_at` (accepted), `approved` (over the bulk ceiling). At most 500 open
  findings; one pending exception per task (409).
- The preview lists each open finding with its tier and end; findings that cannot make the move or already
  have a pending request are left out with the reason. The exception takes the **highest member tier** (never
  below `peer`), the union of the members' exclusions (the owners of any member's asset) and only approvers
  eligible for every member. Each member's acceptance ends at the requested end or **its own cap** when
  shorter (`shortened`).
- The request is one `approval_batches` row plus one pending finding request per member (`batch_id`), in one
  transaction; audit `remediation_task.exception_requested`; the eligible approvers are told in-app.
- Decided once under `/api/v1/approvals/batches`: list and read (`findings:read`, every member in scope),
  `POST /{id}/approve` and `/reject` (`findings:approve`), `/cancel` (the requester, `findings:write`). The
  policy is evaluated again at decision time; the last required approval applies every member (each with its
  own end, cut to its cap now if that is shorter) in one transaction; a member whose finding moved meanwhile is
  canceled, the others still apply. A member request cannot be decided alone (409 `BATCH_MEMBER`). Pending
  exceptions expire at their decision deadline with the hourly job.
- Afterwards each member is an ordinary decision: its own expiry and material-change check. Findings that join
  the task later are not covered.
- Console: the task page offers **Request exception** (with `findings:remediation:write` and `findings:write`
  on an open task whose findings are all visible). The dialog takes the status, the reason code of that status,
  the note (at least the preview's `min_note_length`) and, for an accepted risk, the end (within a year), and
  previews the group as the choices change: the tier and why, who may approve, and every finding with its tier,
  its end ("shortened to its limit" when its cap is earlier) or why it is left out. While an exception is
  pending, the task page shows it (tier, approvals so far, member count, deadline) with a link to the inbox
  instead of the action. The approvals inbox (`/findings/approvals`) has a **Group exceptions** view: one row
  per exception (task, status, tier and approvals, member count, deadline) and a side panel with the members,
  Approve / Reject (reason required) / Cancel (the requester), handled like a single approval (the remaining
  approvals, the refusal reason, re-authentication). A member request in the findings view links to its group
  instead of offering its own Approve / Reject. Strings are in the `findingApprovals` dictionary (en, vi).

## Console

| Page | Shows |
|---|---|
| `/remediation` Fix plan | open tasks and new-fix suggestions in one list ranked by risk left; open, overdue, to-review and my-task counts |
| `/remediation/suggestions` | the inbox: cards with the fix, reach, risk parts, proposed owners and "Why?" (key, algorithm, fix steps); accept, edit then accept, dismiss with a reason (undo), snooze 7 days (undo), bulk accept; keyboard j/k, a, e, d, s, x, ? |
| `/remediation/tasks` | views (all open, mine, verifying, on hold, closed, all), search and sort; a server-paged table or a board by state where only "on hold" moves by drag |
| `/remediation/tasks/{id}` | header (state, deadline and its source, owner, risk left), fix steps with the command to copy, progress, findings grouped by asset in a windowed list that loads as it scrolls, select and Move to… (palette with the server's compatibility warnings) or drag onto a task of the same fix, Split, Mark fixed, Request exception (or the pending exception), hold/resume/cancel, timeline; every move offers Undo |
| `/remediation/campaigns` | the campaigns: programs of tasks (remediation-campaigns.md) |

Strings are in the `remediationHub` dictionary (en, vi). Write actions show only with
`findings:remediation:write` (Mark fixed also `findings:fix_apply`); the API stays the authority. A member with only
`findings:remediation:read` sees "Accept as owner" (and the `a` key) on `join` and `task_route` suggestions, and
nothing else; the API decides whether they own the task and the assets.

## Tasks from a query

Design: RFC-098 §13. The flow:

```
query text --(caller: tenant, user, admin flag, permissions from the request)--> query.Service.MatchFindings
   plan (pkg/querylang: tenant, data scope, pentest member rule, mandatory exclusions)
   + task rules (pgsql.MatchOptions: closed and pentest findings out; unclaimed only for re-run and auto)
   --> QueryExecutor.Match (READ ONLY, 5 s, work_mem cap): count + first 1000 ids
preview: PrimaryHolders (conflicts, shown per the caller's read/write on the holding task) + QueryPreviewStats
create:  CreateTask (members join with source "query", remediation_task_queries row in the same transaction)
re-run / auto: ClaimQueryFindings (lock task, lock findings in id order, keep only free open findings,
         trim to the cap, insert ON CONFLICT DO NOTHING: the primary unique index settles races)
```

The auto include worker (`RemediationTaskQueryController`, every 5 minutes, each task at most every 15)
resolves the stored owner outside a request (active membership, role, permissions) and suspends the task
with a reason instead of running when the owner is gone or lacks `findings:read` +
`findings:remediation:write`, when the task closed, or when the query no longer compiles. Additions and
suspensions are audited (`remediation_task.query_auto_added`, `.query_auto_state_changed`) and the owner gets
an in-app notification (type `remediation_task`).

Console: `CreateTaskFromQueryDialog` (Tasks: "New task from query"; Findings toolbar: "Task from filters",
which converts the list's query string through `POST /api/v1/query/from-filters` and names the params it
could not carry over), with `QueryBox` (field and value completion from `GET /api/v1/query/schema`, live
check through `POST /api/v1/query/explain`), `QueryPreviewPanel` and the shared `ClaimConflictStep` (skip by
default, move with a reason). The task page shows `TaskQueryPanel`: the stored query as plain text, the mode,
the auto state with the suspension reason, pause / resume, and "Re-run query" (adds only after the
confirmation dialog). Strings: the `remediationQuery` dictionary (en, vi).

## Shipped and planned

Shipped: everything above; the solution families page is removed (the Suggestions tab replaces it). The finding
drawer and the finding page show a "Tracked in task" band (`FindingTaskBand`): the task the finding belongs to,
its state and its deadline, linked to the task detail. It reads `GET /remediation/tasks?finding_id=` so the API
data scope applies, and it renders nothing without `findings:remediation:read` or when the finding is in no task.
My Work (`/my-work`) has a Tasks tab (`?tab=tasks`, `MyTasksQueue`) for members with `findings:remediation:read`:
the open, in-progress, verifying and on-hold tasks assigned to the caller or to one of their groups
(`assignee=me`), earliest deadline first, with "View all tasks" opening the Tasks "mine" view. The page's strings
are in the `myWork` dictionary (en, vi).

## Key files

- `api/migrations/*_remediation_tasks.up.sql`, `*_remediation_task_activity_type*.sql` (finding activity type)
- `api/pkg/domain/remediation/task.go`, `task_repository.go`
- `api/internal/infra/postgres/remediation_task_repository.go`, `remediation_claim.go` (claim conflicts)
- `api/pkg/domain/remediation/claim.go`, `api/internal/app/remediation/claims.go`
- `api/internal/app/remediation/tasks.go`
- `api/internal/infra/http/handler/remediation_task_handler.go`, `routes/remediation.go`
- `api/internal/infra/controller/remediation_tasks.go`
- `api/migrations/*_remediation_suggestions.up.sql`
- `api/pkg/domain/remediation/suggestion.go` (generator rules), `api/internal/app/remediation/suggestions.go`,
  `api/internal/infra/postgres/remediation_suggestion_repository.go`,
  `api/internal/infra/http/handler/remediation_suggestion_handler.go`,
  `api/internal/infra/controller/remediation_suggestions.go`
- `api/tests/integration/remediation_tasks_test.go`, `remediation_suggestions_test.go`, `remediation_claim_test.go`
- Tasks from a query: `api/migrations/*_remediation_task_queries.*.sql`, `api/pkg/domain/remediation/task_query.go`,
  `api/internal/app/remediation/query_tasks.go`, `api/internal/app/query/match.go`, `api/pkg/querylang/pgsql/match.go`,
  `api/internal/infra/postgres/remediation_task_query_repository.go`,
  `api/internal/infra/http/handler/remediation_task_query_handler.go`, `query_from_filters_handler.go`,
  `api/internal/infra/controller/remediation_task_query.go`, `api/tests/integration/remediation_task_query_test.go`
