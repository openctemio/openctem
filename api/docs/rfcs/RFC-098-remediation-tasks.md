# RFC-098: Remediation actions, tasks and suggestions

| | |
|---|---|
| Status | Accepted (2026-10-15). Implemented: the task model (actions, tasks, primary and related membership, derived state, task deadline, timeline, API with data scope); the suggestions engine (deterministic keys, owner partitions, ranking, lifecycle, dismissal memory, daily cap, digest); accept flows (as is, edited, bulk, and as the asset owner without write access) and the auto-join rule; moves, split, merge and detach; task-level mark fixed and regression tasks; the Remediation console (Fix plan, Suggestions, Tasks, Campaigns, task detail); the finding drawer band; the My Work tasks tab; claim conflicts (409 with per-finding details, skip or audited move); tasks from a query (API: preview, create in snapshot or auto mode, re-run, auto include with suspension; §13) |
| Scope | api, web |
| Related | RFC-015 (remediation groups: the candidate keys), RFC-006 (ticketing), RFC-039 (retest and SLA restart), RFC-097 (ticket field and status mapping) |

## 1. Summary

A **remediation action** is *what* fixes a set of findings: one upgrade (`upgrade:pypi:django:4.2.30`), one
secret rotation (`rotate:secret:<fingerprint>`), or a fix a person named. A **remediation task** is *who* does
that fix and *by when*: one owner (a user and/or a group), a deadline and a state derived from its findings.
A **campaign** stays a program lens over tasks ("all exposures to CVE-X by Friday") whose deadline can only
tighten the tasks' deadlines.

```
campaign (optional, a program lens with a deadline)
  └── remediation action (WHAT fixes it)          created only by a person
        └── remediation task (WHO, BY WHEN)        the work unit: owner, deadline, ticket
              └── member findings (WHERE)          each with its own status and verification
```

Grouping algorithms only **suggest**; a person accepts (with edits) and nothing is created by an algorithm on
its own (§5).

## 2. Data model

| Table | Holds |
|---|---|
| `remediation_actions` | `action_key` (unique per tenant), `kind` (`upgrade`, `rotate`, `sol`, `manual`), title, `fix_spec`, `origin` (`manual` or `suggestion`) |
| `remediation_tasks` | action, campaign, title, description, assignee user and group, manual state (`on_hold`, `canceled`) and note, derived `state`, effective `deadline` and its source, a person's `manual_deadline`, member counters, `risk_points`, `regression_of`, archive mark, `version` |
| `remediation_task_members` | task, finding, `role` (`primary` or `related`), how it joined, when it left and why; history is never deleted |
| `remediation_task_events` | the task timeline: one entry per operation |

A finding is the **primary** member of at most one active task (a partial unique index on
`(tenant_id, finding_id) WHERE left_at IS NULL AND role = 'primary'`). It can be a **related** member of other
tasks ("also fixed by"): no state, no deadline and no ticket effect. Every membership change writes a
`remediation_task_changed` entry on the finding's own timeline. A hand-made task gets its own action
(`manual:<task id>`), so two hand-made tasks never share an action by accident.

## 3. Derived state

The task state is a pure function of the members (counted over active primary members) and two manual flags,
first match wins:

| State | Rule |
|---|---|
| `archived` | the task lost its last member to a move |
| `canceled` | a person canceled it (a reason is required); its findings are released and may join another task |
| `on_hold` | a person put it on hold |
| `done` | every member is closed **and at least one is verified fixed** (resolved by a covered scan, a retest or a reviewer with `findings:verify`) |
| `closed_unverified` | every member is closed but none was verified fixed (accepted, false positive, duplicate, or resolved without proof) |
| `verifying` | every open member is claimed fixed (`fix_applied`) and awaits its own verification |
| `in_progress` | some member is in progress or claimed fixed |
| `open` | otherwise |

`done`, `closed_unverified`, `canceled` and `archived` are terminal: no edits and no new members. A member
that regresses after `done` opens a new task linked by `regression_of`; the closed task is never reopened, so
time-to-fix metrics stay honest.

The state is recomputed in the same transaction as every change a person makes, and by the
`remediation-tasks` controller (every two minutes) for the tasks whose member findings changed since their last
recompute (a scan closed one, a fix claim, an SLA change).

## 4. Deadline and risk

- `deadline = min(earliest open member SLA deadline, manual deadline, campaign due date)`. Taking the minimum
  is what makes a manual or campaign deadline **tighten only**: neither can move a member's own deadline
  later. `deadline_source` names the winner (`member`, `manual`, `campaign`). A task with no open member has no
  deadline.
- `risk_points` is the risk left in the task: the sum over open primary members of the priority class weight
  (P0 8, P1 4, P2 2, P3 1), or the severity weight for an unclassified finding (critical 4, high 2, medium and
  low 1). The same weight ranks suggestions by risk reduced.
- Member SLAs stay per finding and remain the ones counted in SLA compliance (no double counting).

## 5. Suggestions

Algorithms propose; a person with permission accepts.

- **Kinds:** `new_group` (a deterministic key with no accepted action: "Upgrade django to 4.2.30 fixes 22
  findings on 14 assets"), `join` (new findings with the key of an accepted action), `task_route` (members of an
  accepted action without a task, partitioned by owner).
- **Deterministic keys first:** the remediation keys of RFC-015 (package and fixed version, secret
  fingerprint, specific solution text), then KB/OS package, base image, IaC module/control and rule+file as
  their data arrives. Owner partitioning by the asset's primary owner (the RACI owner model) and a default
  queue.
- **Ranking:** risk reduced, then member count, then the earliest SLA deadline.
- **Lifecycle:** `proposed` → `accepted` | `dismissed` (reason required) | `snoozed` (until a date) |
  `superseded` | `expired`. Identity is a fingerprint of kind, key, target and owner; a dismissed suggestion
  comes back only on a material change (members up 50 % or 10, risk doubled, a member became P0/KEV, a new fix
  target). Removed members are remembered per action.
- **Noise control:** minimum two members (one for P0/KEV), at most 50 new suggestions per tenant per day,
  dedup against accepted actions (a key with an accepted action becomes a `join`, never a second action), a
  daily digest notification to reviewers instead of per-suggestion pings.
- **Never applied:** a suggestion holds finding ids and a proposed owner per partition; it creates nothing.
  Findings that are already the primary member of an active task, closed findings and pentest findings are
  never candidates. A finding a person took out of a fix (removed before accepting, detached, moved away) is
  recorded in `remediation_key_exclusions` and not proposed for that key again.
- **Runs:** every 15 minutes for each tenant with keyed findings and the remediation module on, and on demand
  (at most once a minute per tenant). One run is one transaction under a per-tenant lock: open suggestions with
  the same identity are updated in place, a snoozed one past its date is proposed again, open suggestions the
  run no longer produces expire, and held-back proposals are surfaced up to the daily cap.

## 6. Accept flows

1. **Accept as is:** creates the action and one task per owner.
2. **Edit, then accept:** remove members, change the owner, title or deadline (tighter only).
3. **Bulk accept** a filtered set, behind the bulk abuse guard.
4. **Auto-join rule**, opt-in per accepted action, for deterministic keys only: new findings with the exact
   key join an `open` or `in_progress` task with the same owner; a `verifying` or closed task gets a `join`
   suggestion instead. Auto-join never changes a finding's status and never closes anything; a per-action daily
   cap falls back to suggestions.

Each accept is one transaction: the suggestion is locked at the version the person saw (409 when it changed),
its findings are claimed (§6.1): findings that closed since are left out and listed (`dropped`); findings that
joined another active task since refuse the accept unless the request skips or moves them. Removed findings go to `remediation_key_exclusions`. Bulk accept takes up to 50
suggestions and 5000 findings, each on its own. Turning auto-join on needs a caller with access to every asset
(the rule acts on findings they may not see); `upgrade` and `rotate` keys only (also a table CHECK).

### 6.1 Claim conflicts

A finding is the primary member of at most one active task (`ux_remediation_task_members_primary`). Every path
that adds primary members (accepting a suggestion, creating a task, adding members) claims the findings in its
transaction: the tasks to move out of are locked in id order, then the findings in id order; each finding is
closed (an accept drops it and lists it), free, or taken by another active task. A taken finding refuses the
whole request with 409:

```
{"code": "FINDINGS_IN_OTHER_TASK", "message": "...", "details": {"conflicts": [
  {"finding_id": "...", "finding_title": "...", "task_id": "...", "task_title": "..." | null,
   "assignee_user_id": "..." | null, "assignee_group_id": "..." | null, "can_move": true | false}]}}
```

`task_title` and the assignee are null when the caller cannot read the holding task (they learn only that the
finding is taken). `can_move` is true when the caller holds `findings:remediation:write` and may change the
holding task (it is visible and none of its findings is outside their scope). The request resolves conflicts
with one field, the same on every path: `"conflicts": {"skip": true}` leaves every taken finding out (listed
in `skipped` on an accept), and `"conflicts": {"move": [ids], "move_reason": "..."}` moves the named findings
and skips the others. A move needs a reason (at most 500 characters) and write access to every holding task
(403 otherwise); it ends the source membership (`left_reason = 'moved'`, history kept), writes a timeline entry
on the finding and on both tasks, recomputes the source (archived when emptied), keeps the finding's SLA, writes
one `remediation_task.findings_moved` audit row per source task and tells the trackers of both tasks. Related
links carry no status and are never a conflict. Of two concurrent claims of one finding exactly one wins (the
finding rows are locked; the unique index is the backstop) and the other answers 409.

## 7. Moves, split, merge, detach

- **Move** findings to another task; **split** a task by owner, asset or batch; **merge** tasks of the same
  action; **detach** findings (back to the pool, pinned so suggestions do not propose them again).
- Never allowed: another tenant, a closed or archived target, findings outside the caller's scope. Allowed with
  a warning the person confirms: a different fix action or a different owner.
- Both tasks are recomputed in the same transaction; a task emptied by moves is archived with a note; every
  finding and both tasks get a timeline entry; the tickets of both tasks get a comment through the ticketing
  service; the request carries each task's `version` (409 when stale); finding rows are locked in id order.
- Shipped: `POST /api/v1/remediation/moves/preview` returns the warnings (`different_fix`, `different_owner`,
  `target_verifying`, `source_verifying`, `empties_source`); `POST /api/v1/remediation/moves` needs
  `confirm: true` when there are any (else 409 `MOVE_NEEDS_CONFIRMATION` with the warnings) and returns both
  tasks with their new versions, so the undo is the reverse move. No `to_task_id` detaches: the findings return
  to the pool and are excluded from that fix's suggestions. `POST /tasks/{task_id}/splits` creates a task of
  the same fix (campaign and manual deadline kept; owner kept unless named) for some findings (at least one
  stays); `POST /tasks/{task_id}/merges` moves every finding of up to 20 same-fix tasks into it and archives
  them. Archived tasks are not restored (a move into them is refused).
- Ticket comments: after a move, split, merge or detach is stored, the task service hands a `TaskMoveEvent`
  (kind, source and target task with titles, finding count, source archived) to its `TaskMoveNotifier`;
  `TaskMoveEvent.Comments()` gives one comment per task touched (source and target), with counts and task titles
  only, never finding identifiers or titles (people who see the issue may not see every finding). The ticket
  integration implements the notifier for tasks that carry an issue; the call is best effort and never fails or
  undoes the move. Until it is wired, a move writes the task timeline only.

## 8. Mark fixed at task level

"Mark fixed" claims the fix for every open, in-scope member: each goes to `fix_applied` through the legal
steps of the finding bulk path (the same path as a group resolve: a note, `findings:fix_apply`, the abuse
guard) and a proof-of-fix re-check is queued per member. Only per-member evidence closes a finding. A failed
verification puts the member, and so the task, back in progress.

Shipped: `POST /api/v1/remediation/tasks/{task_id}/resolve` (`findings:remediation:write` and
`findings:fix_apply`) with the task `version` and a note; the caller must see every finding of the task. The
response names each finding not updated and why (not the caller's asset, already claimed, illegal step).
Regressions: when a finding of a `done` or `closed_unverified` task reopens, the recompute moves the reopened
findings into a new task (`Regression: <title>`, same fix, owner, campaign and manual deadline,
`regression_of` = the closed task); the closed task keeps its state and history.

## 9. Tickets

One ticket per task. The tracker field and status mapping is RFC-097 (object kind `task`); the task model
gives it the task's state, deadline and members. A tracker "Done" is a fix claim (task-level mark fixed),
never a close.

Implemented (built-in map; task profiles follow): a person who may change the task (every member in their data
scope, `remediation:write`) creates its Jira issue in a project configured for ticketing; one active issue per
task (a per-task guard covers two clicks at once). The issue carries the task's title, fix, finding count,
deadline and a link back, and names no finding. The link is a `ticket_links` row with `task_id` (one object per
link, composite tenant foreign key) and the task state last pushed. The task ticket controller pushes every task
whose state differs from that state, each in its own tenant, once a minute: in progress → "In Progress", done or
closed without a verified fix → "Done", every move with a progress comment; a state without a status (verifying,
on hold, canceled) or a workflow without the move gets the comment alone. A transient tracker error is retried on
the next pass; a refusal is not. Inbound, a status change of the task's issue applies to the task's open primary
findings through the finding service (Done is a fix claim for each); the echo of our own move (the status we
pushed, within ten minutes) is ignored. `SyncService.TaskChanged` pushes a task at once for a caller that wants it
before the next pass.

## 10. API

```
GET   /api/v1/remediation/tasks                          list (state, assignee=me, group, action, campaign, finding, search, sort)
POST  /api/v1/remediation/tasks                          create from findings (409 FINDINGS_IN_OTHER_TASK unless conflicts resolves it, §6.1)
GET   /api/v1/remediation/tasks/{task_id}
PATCH /api/v1/remediation/tasks/{task_id}                title, description, owner, deadline, campaign, hold/resume/cancel; version required
GET   /api/v1/remediation/tasks/{task_id}/members
POST  /api/v1/remediation/tasks/{task_id}/members        add primary or related findings; version required; conflicts (§6.1)
POST  /api/v1/remediation/tasks/{task_id}/resolve        mark fixed: each open finding claimed fixed and re-checked
GET   /api/v1/remediation/tasks/{task_id}/ticket-links   the task's tracker issue links
POST  /api/v1/remediation/tasks/{task_id}/ticket-links   create the task's Jira issue (409 when it has one)
POST  /api/v1/remediation/tasks/{task_id}/splits         split findings into a new task of the same fix
POST  /api/v1/remediation/tasks/{task_id}/merges         merge tasks of the same fix
POST  /api/v1/remediation/moves[/preview]                move findings between tasks (or out of any)
GET   /api/v1/remediation/tasks/{task_id}/timeline
POST  /api/v1/remediation/tasks/query/preview            preview a task from a query (read-only; §13)
POST  /api/v1/remediation/tasks/query                    create a task from a query, snapshot or auto (409 FINDINGS_IN_OTHER_TASK)
GET   /api/v1/remediation/tasks/{task_id}/query          the stored query, mode and auto state
POST  /api/v1/remediation/tasks/{task_id}/query/rerun[/preview]  new matches; added only on confirmation
POST  /api/v1/remediation/tasks/{task_id}/query/auto     pause or resume auto include
POST  /api/v1/query/from-filters                         a findings list filter as query text
GET   /api/v1/remediation/suggestions                    list, best first (state, kind, key_kind, min_risk, search, queued)
GET   /api/v1/remediation/suggestions/stats              open, held back and snoozed counts (the inbox badge)
POST  /api/v1/remediation/suggestions/run                run the generator now (at most once a minute; 429 otherwise)
GET   /api/v1/remediation/suggestions/{id}               with the explanation (key, fix spec, partitions, risk parts, confidence)
PATCH /api/v1/remediation/suggestions/{id}               snooze (snoozed_until, at most 180 days); version required
GET   /api/v1/remediation/suggestions/{id}/members
POST  /api/v1/remediation/suggestions/{id}/reject        dismiss with a reason; version required
POST  /api/v1/remediation/suggestions/{id}/reopen        undo a dismissal or a snooze
POST  /api/v1/remediation/suggestions/{id}/approve       accept, optionally edited (title, removed findings, owners, deadline, auto_join); conflicts (§6.1)
POST  /api/v1/remediation/suggestions/approve            accept several as they are
GET   /api/v1/remediation/actions/{id}
PATCH /api/v1/remediation/actions/{id}                   auto_join on or off
```

Reads need `findings:remediation:read` (members also `findings:read`); changes need
`findings:remediation:write`, with one exception (owner decision D10): an asset owner with only
`findings:remediation:read` may accept, as it is, a `join` into their own task or a `task_route` to them (or
one of their groups) when every finding is in their scope and on an asset they own; a new fix, edits and
auto-join stay with write. Marking findings fixed will also need `findings:fix_apply`. The routes are in the
`remediation` module.

## 11. Authorization, tenant isolation and threat model

- **Tenant:** every table carries `tenant_id`; every statement filters on it; member reads join findings on the
  same tenant; the tenant comes from the authenticated principal, never the request.
- **Data scope:** a restricted member sees a task only through its findings in their scope; the counters,
  deadline and risk are computed over those findings and `hidden_members` counts the rest. A task with none of
  their findings answers 404. They may change only a task whose findings are all in their scope, and every
  finding they name must be in their scope (one not-found answer for another tenant's finding, a missing one
  and an out-of-scope one).
- **Owner checks:** an assignee must be an active member of the organization and a group must be one of its
  groups; a campaign must be one of its campaigns (one answer each, no oracle for other organizations' ids).
- **Mass change:** grouping never changes a finding's status; marking findings fixed goes through the finding
  bulk path with its permission, note and abuse guard; closing comes only from per-member verification.
- **Concurrency:** every change carries the task `version`; the task row and the finding rows are locked in a
  fixed order; the background recompute locks the tasks it writes.
- **Claim conflicts (§6.1):** the 409 names the holding task's title and owner only to a caller who can read
  it; moving needs write access to the holding task, checked before the transaction and again inside it (a
  finding that changed task since is refused, not moved); another tenant's finding is not found.
- **Suggestions:** a restricted member sees a suggestion only through its findings in their scope; the ids
  and owner partitions of the others are not returned (`hidden_members` counts them), and they may not decide
  on it. The generator runs as the platform but writes only proposals.
- **Audit:** `remediation_task.created`, `.updated`, `.members_added`, `.state_changed` (hold, resume, cancel);
  `remediation_task.members_moved`, `.findings_moved` (a resolved claim conflict, one row per source task), `.split`, `.merged`, `.fix_claimed`; `remediation_suggestion.refreshed`, `.dismissed`, `.snoozed`, `.reopened`, `.accepted`;
  `remediation_action.auto_join_changed`; `remediation_task.created_from_query`, `.query_rerun`,
  `.query_auto_added`, `.query_auto_state_changed` (each with the query text).

## 12. Rollout

| Step | Content | Status |
|---|---|---|
| 1 | Task model, derived state, deadline, membership, timeline, API with data scope | Implemented |
| 2 | Suggestions engine (deterministic keys, owner partition, ranking, lifecycle, dedup, dismissal memory, rate limit, digest) | Implemented |
| 3 | Accept flows (as is, edit, bulk, auto-join rule; asset owners accept their own join or task route as is) | Implemented |
| 4 | Moves, split, merge, detach with compatibility rules, undo; the ticket comment hook (wired by the task ticket integration) | Implemented |
| 5 | Task-level mark fixed and regression tasks | Implemented |
| 6 | Console: Fix plan, Suggestions, Tasks, Campaigns, My queue; task detail; Move palette | Implemented |
| 7 | Finding drawer band: the task a finding is tracked in, its state and deadline | Implemented |
| 8 | My Work tasks tab: my open tasks (mine or my groups), earliest deadline first | Implemented |
| 9 | Tasks from a query (§13): preview, snapshot and auto modes, re-run, auto include worker | Implemented (console: "New task from query" on Tasks, "Task from filters" on Findings, the task's "Created from a query" panel; "Add findings by query" in the suggestion edit dialog is open) |

## 13. Tasks from a query

A person selects the findings of a task with a custom query (RFC-115) instead of picking them: from the
findings list ("Create task from these filters": the list filter becomes query text through
`POST /api/v1/query/from-filters`, one filter in two views), from the suggestion "Edit, then accept"
dialog ("Add findings by query"), or from a query box on the task create dialog.

**Selection.** Only `findings where ...` qualifies (no pipeline stages). The query runs as the creator: the
query service resolves the principal on the server (tenant, data scope, the pentest member rule, the
mandatory exclusions of RFC-115) and the task layer adds two rules of its own: closed findings and pentest
findings are left out (a pentest finding is fixed through its pentest campaign, and its visibility is
member-only). The same limits apply as for interactive queries (per-user rate limit, concurrency caps,
read-only transaction, 5 s statement timeout, `work_mem` cap). A task holds at most 1000 findings from a
query; more matches answer `400 QUERY_TOO_MANY_MATCHES`: narrow the query, or split the work into several
tasks under a campaign.

**Preview** (read-only, claims nothing): the number of matches, counts by severity, the top assets and the top
primary owners of those assets, a sample of 20, the earliest SLA deadline, a suggested assignee (the most
common primary owner) and the matches other active tasks hold. A conflict shows the holding task's title and
owner only when the caller may read that task, and `can_move` only when the caller may change it.

**Create.** The task stores the canonical query text and its language version
(`remediation_task_queries`: text, version, mode, auto state and reason, cap, owner, last run, counters),
and its members join with source `query`. Matches other active tasks hold answer
`409 FINDINGS_IN_OTHER_TASK` with `details.conflicts` (the shared shape) unless the request carries
`"conflicts": {"skip": true}` or `{"move": [...], "move_reason": "..."}`; a move goes through the audited move
(timeline on both tasks, owners told, SLA kept). The partial unique index on primary membership decides
concurrent claims: exactly one wins.

**Modes.** *Snapshot* (default) holds the matches at creation. "Re-run" previews the new matches no active
task holds and adds them only when the person confirms. *Auto* adds new matches by itself, every 15 minutes
at most, with guardrails: only findings no other active task holds (never taken), up to the task's cap
(1 to 1000), the owner is told of additions in-app, and a person may pause and resume it.

**Who an auto run acts as.** Always the creator (the stored owner), with their membership, role and
permissions read again on every run, and their current data scope applied by the query service. The task is
suspended, audited and shown on the task with the reason, never run ownerless, when:
the owner left the organization or the account was deleted (`owner_removed`), the owner no longer holds
`findings:read` and `findings:remediation:write` (`owner_lost_access`), the task closed (`task_closed`), or the
stored query no longer compiles for the owner (`query_invalid`). A suspended task resumes only once its
cause is gone.

**Who sees the findings.** Assignees see the task's findings through the assignment view grant (the
assignment-grants-view work); everyone else sees a task through its findings in their own scope, the rest
as a count (§11).

**Threat model.** A crafted query cannot widen its scope: the text never carries the principal, the plan
layer injects every rule, and executors cannot build a plan. A client cannot name another tenant (the caller
is built from the authenticated request and checked against the tenant). A creator cannot keep reading
findings after losing access through an auto task: each run re-reads their access and suspends. A task from a
query cannot silently take a finding from another person's task: conflicts are explicit (skip or audited
move) and auto mode only adds unclaimed findings. Cost is bounded by the query limits and the 1000 cap.
