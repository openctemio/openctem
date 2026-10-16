# RFC-098: Remediation actions, tasks and suggestions

| | |
|---|---|
| Status | Accepted (2026-10-15). Implemented: the task model (actions, tasks, primary and related membership, derived state, task deadline, timeline, API with data scope); the suggestions engine (deterministic keys, owner partitions, ranking, lifecycle, dismissal memory, daily cap, digest). Designed: accept flows, moves/split/merge, task-level "mark fixed", the new Remediation console |
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
| `verifying` | every open member is claimed fixed (`fix_applied`, `validated_fixed`) and awaits its own verification |
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

## 6. Accept flows (designed)

1. **Accept as is:** creates the action and one task per owner.
2. **Edit, then accept:** remove members, change the owner, title or deadline (tighter only).
3. **Bulk accept** a filtered set, behind the bulk abuse guard.
4. **Auto-join rule**, opt-in per accepted action, for deterministic keys only: new findings with the exact
   key join an `open` or `in_progress` task with the same owner; a `verifying` or closed task gets a `join`
   suggestion instead. Auto-join never changes a finding's status and never closes anything; a per-action daily
   cap falls back to suggestions.

## 7. Moves, split, merge, detach (designed)

- **Move** findings to another task; **split** a task by owner, asset or batch; **merge** tasks of the same
  action; **detach** findings (back to the pool, pinned so suggestions do not propose them again).
- Never allowed: another tenant, a closed or archived target, findings outside the caller's scope. Allowed with
  a warning the person confirms: a different fix action or a different owner.
- Both tasks are recomputed in the same transaction; a task emptied by moves is archived with a note; every
  finding and both tasks get a timeline entry; the tickets of both tasks get a comment through the ticketing
  service; the request carries each task's `version` (409 when stale); finding rows are locked in id order.

## 8. Mark fixed at task level (designed)

"Mark fixed" claims the fix for every open, in-scope member: each goes to `fix_applied` through the legal
steps of the finding bulk path (the same path as a group resolve: a note, `findings:fix_apply`, the abuse
guard) and a proof-of-fix re-check is queued per member. Only per-member evidence closes a finding. A failed
verification puts the member, and so the task, back in progress.

## 9. Tickets

One ticket per task. The tracker field and status mapping is RFC-097 (object kind `task`); the task model
gives it the task's state, deadline and members. A tracker "Done" is a fix claim (task-level mark fixed),
never a close.

## 10. API

```
GET   /api/v1/remediation/tasks                          list (state, assignee=me, group, action, campaign, finding, search, sort)
POST  /api/v1/remediation/tasks                          create from findings (409 FINDINGS_IN_OTHER_TASK)
GET   /api/v1/remediation/tasks/{task_id}
PATCH /api/v1/remediation/tasks/{task_id}                title, description, owner, deadline, campaign, hold/resume/cancel; version required
GET   /api/v1/remediation/tasks/{task_id}/members
POST  /api/v1/remediation/tasks/{task_id}/members        add primary or related findings; version required
GET   /api/v1/remediation/tasks/{task_id}/timeline
GET   /api/v1/remediation/suggestions                    list, best first (state, kind, key_kind, min_risk, search, queued)
GET   /api/v1/remediation/suggestions/stats              open, held back and snoozed counts (the inbox badge)
POST  /api/v1/remediation/suggestions/run                run the generator now (at most once a minute; 429 otherwise)
GET   /api/v1/remediation/suggestions/{id}               with the explanation (key, fix spec, partitions, risk parts, confidence)
PATCH /api/v1/remediation/suggestions/{id}               snooze (snoozed_until, at most 180 days); version required
GET   /api/v1/remediation/suggestions/{id}/members
POST  /api/v1/remediation/suggestions/{id}/reject        dismiss with a reason; version required
POST  /api/v1/remediation/suggestions/{id}/reopen        undo a dismissal or a snooze
```

Reads need `findings:remediation:read` (members also `findings:read`); changes need
`findings:remediation:write`. Marking findings fixed will also need `findings:fix_apply`. The routes are in the
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
- **Suggestions:** a restricted member sees a suggestion only through its findings in their scope; the ids
  and owner partitions of the others are not returned (`hidden_members` counts them), and they may not decide
  on it. The generator runs as the platform but writes only proposals.
- **Audit:** `remediation_task.created`, `.updated`, `.members_added`, `.state_changed` (hold, resume, cancel);
  `remediation_suggestion.refreshed`, `.dismissed`, `.snoozed`, `.reopened`.

## 12. Rollout

| Step | Content | Status |
|---|---|---|
| 1 | Task model, derived state, deadline, membership, timeline, API with data scope | Implemented |
| 2 | Suggestions engine (deterministic keys, owner partition, ranking, lifecycle, dedup, dismissal memory, rate limit, digest) | Implemented |
| 3 | Accept flows (as is, edit, bulk, auto-join rule) | Designed |
| 4 | Moves, split, merge, detach with compatibility rules, tickets comments, undo | Designed |
| 5 | Task-level mark fixed and regression tasks | Designed |
| 6 | Console: Fix plan, Suggestions, Tasks, Campaigns, My queue; task detail; Move palette | Designed |
