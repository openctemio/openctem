# Remediation Campaigns

Design: [RFC-098 §9a](../rfcs/RFC-098-remediation-tasks.md). Code: `pkg/domain/remediation/campaign.go`,
`internal/app/exposure/remediation_campaign.go`, `internal/infra/postgres/remediation_campaign_repository.go`,
`internal/infra/http/handler/remediation_campaign_handler.go`.

## What a campaign is

A campaign is a **program of remediation tasks** with one owner (`assigned_to`, an active member, and an optional
team `assigned_team`), a priority, a start and a due date. A task is in at most one campaign
(`remediation_tasks.campaign_id`, `ON DELETE SET NULL`). A campaign **never holds findings**: a finding is in at
most one active work unit, the primary membership of a task, so "which findings does this campaign cover" is
always "the findings of its tasks".

```
campaign (program: owner, due date)
  └── remediation task (unit of work: owner, deadline, state derived from its findings)
        └── member findings (each with its own status, SLA and verification)
```

## Summary (derived, never stored)

Every read derives the summary from the campaign's tasks (archived tasks left out) and their active members, over
the reader's data scope (`CampaignRepository.Summaries`, one query per page):

| Field | Meaning |
|---|---|
| `tasks` | tasks the reader can see (a finding in their scope; for a reader who is not restricted also a task with no member, such as a canceled one) |
| `live_tasks` | open, in progress, verifying or on hold |
| `done_tasks` | state `done` (every finding closed, one verified fixed) |
| `overdue_tasks` | live and past their deadline (an open finding past its SLA, or a manual or campaign deadline passed) |
| `hidden_tasks` | tasks with no finding in the reader's scope: a count only |
| `findings`, `closed_findings`, `verified_findings` | primary members of the visible tasks, in the reader's scope |
| `progress` | `closed_findings / findings` in percent |

The campaign's owner sees the whole campaign's counts (assignment grants view of the program), not the tasks
they cannot otherwise open.

## Lifecycle

`draft` → `active` → `completed`; `canceled` from draft or active; `completed` → `active` (reopen). The database
refuses any other status (`chk_remediation_campaigns_status`).

- **Complete** needs the organization-wide summary to be done: tasks exist, none is live, one is done
  (`CampaignSummary.IsDone`). Otherwise 400.
- **Reconcile** (`remediation-progress` controller, every 30 minutes, tenants with the remediation module on):
  an active campaign whose tasks are done completes; a completed campaign with a live task again (a regression
  task keeps its campaign) reopens. Both are audited as `trigger: auto_complete` / `auto_reopen`, actor system.
- **Due date** can only move earlier (`ErrCampaignDeadlineOnlyTightens`). While the campaign is draft or active it
  bounds the deadline of every task (`deadline = min(member SLA, manual, campaign due)`, source `campaign`); a
  change re-derives its tasks' deadlines at once, and a completed or canceled campaign stops bounding them.
- Canceling or deleting a campaign never changes its tasks: they stay, and leave it on delete.

## Adding and removing tasks

- `POST /api/v1/remediation/campaigns/{id}/tasks {task_ids, move}`: the campaign must be draft or active and
  writable by the caller, and so must every task (`TaskService` write check: visible, no finding outside the
  caller's scope). A task already in another campaign answers **409 `TASKS_IN_OTHER_CAMPAIGN`** with
  `details.tasks[] {task_id, campaign_id, campaign_name (null when the caller cannot see it), can_move}` unless
  `move` is set; moving needs the caller to be able to change that campaign too. At most 200 tasks per request.
- `DELETE /api/v1/remediation/campaigns/{id}/tasks/{task_id}`: the task leaves the campaign.
- `POST /api/v1/remediation/campaigns` takes optional `task_ids` and `move` with the same checks, made before the
  campaign is stored.
- A task's own `PATCH /api/v1/remediation/tasks/{id} {campaign_id}` goes through the same campaign check
  (`TaskCampaignGate`).
- Each change bumps the task's version and writes an `updated` entry on its timeline; the campaign gets an
  `remediation_campaign.updated` audit row naming the tasks added or removed.
- The add-tasks picker lists `GET /api/v1/remediation/tasks?no_campaign=true`.

## API

```
GET    /api/v1/remediation/campaigns                       list + status_counts (status, priority, search, page, per_page)
POST   /api/v1/remediation/campaigns                       create (task_ids, move)
GET    /api/v1/remediation/campaigns/{id}
PATCH  /api/v1/remediation/campaigns/{id}                  fields; version
PATCH  /api/v1/remediation/campaigns/{id}/status           {status: active|completed|canceled, version}
POST   /api/v1/remediation/campaigns/{id}/tasks            {task_ids, move}
DELETE /api/v1/remediation/campaigns/{id}/tasks/{task_id}
POST   /api/v1/remediation/campaigns/{id}/create-ticket    Jira epic (remediation-campaign-jira-sync.md)
DELETE /api/v1/remediation/campaigns/{id}
```

Reads need `findings:remediation:read`, changes `findings:remediation:write`; the routes are in the `remediation`
module. Every response carries `summary` and `can_edit` (the caller may change it).

## What a restricted member sees

- **Visible:** a campaign they created, one they own (`assigned_to`), or one with a task that has a finding in
  their scope. Any other campaign answers 404 on every route and is not listed or counted.
- **Writable:** a visible campaign none of whose tasks has a finding outside their scope (403 otherwise). An
  empty campaign they created or own is writable.
- Out-of-scope tasks are a count (`hidden_tasks`); their titles, owners and findings are never returned.

## Threat model

| Threat | Control |
|---|---|
| Cross-tenant read or change | every query filters on `tenant_id`; tasks join campaigns on `(tenant_id, id)` (composite foreign key); another tenant's id answers 404 |
| A restricted member widens their reach through a campaign | visibility and write checks over the tasks' findings; adding a task needs write on the task; moving needs write on the source campaign |
| Leaking another team's work through counts or a conflict answer | hidden tasks are a count; a conflict names a campaign only when the caller can see it |
| One finding in two work units | campaigns hold no findings; the unique primary-membership index on tasks decides |
| Silent loss of filter campaigns | the conversion below audits every campaign and its conflicts and notifies owners and admins |

## Audit trail

`remediation_campaign.created`, `.updated` (field diff, or `tasks_added` / `tasks_removed`), `.status_changed`
(`trigger`: manual, auto_complete, auto_reopen, status_retired), `.deleted`, and `.migrated` (the conversion). A
failed audit write is logged and never fails the change.

## Conversion

Until 2026-10 a campaign tracked findings through a `finding_filter` evaluated on every read. Migration
`remediation_campaigns_hold_tasks` turned what each running campaign (draft, active, paused, validating) tracked
into tasks, evaluating the filter exactly as the API did (a fix key tracks its solution family; otherwise a CVE,
finding id, asset or tool is needed; an unparseable filter tracks nothing):

- only open findings moved (not closed ones, not unpublished pentest drafts or findings in review);
- a finding tracked by two campaigns went to the campaign furthest along (active or validating, then paused, then
  draft), then the oldest: work that started wins over a plan nobody started, and among equals the first claim
  wins, as every task claim does;
- a finding already the primary member of a task did not move: a live task without a campaign joined the
  campaign, a task of another campaign kept it and the claim was recorded as a conflict;
- the other findings became one task per campaign (manual action, title = campaign name, owner = the campaign's
  assignee while an active member, and its team; no manual deadline: the campaign's due date bounds its tasks);
- report: an audit row per campaign (`remediation_campaign.migrated`: outcome, findings moved, tasks joined, every
  conflict up to 100 and their count, the original filter), a timeline entry on each task that joined a campaign
  (`updated`) or kept another campaign's claim (`campaign_conflict`), a `remediation_task_changed` entry on each
  moved finding, one notice to the owners and admins, and a summary in the migration output.

Campaigns whose filter named only severities, sources, statuses or search text tracked nothing (research 188
C-003) and hold no task: their audit row says so.

Migration `remediation_campaigns_drop_finding_filter` ran the conversion once more for campaigns created in
between, mapped `paused` and `validating` to `active` (audited), dropped the conversion functions and the columns
`finding_filter`, `finding_count`, `resolved_count`, `progress`, `risk_score_*`, `risk_reduction`, and added the
status check. Its down brings the columns back empty (lossy).
