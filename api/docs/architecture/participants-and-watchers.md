# Participants and watchers

Design: [RFC-120](../rfcs/RFC-120-participants-and-watchers.md). This page describes what is built.

A finding has one assignee; a remediation task has one owner (a user or a team). Other people who
should hear about an item are **watchers**. Watching grants nothing: it never gives access to a
finding or a task.

## Data

Table `work_item_subscriptions` (one row per person and item):

| Column | Meaning |
|---|---|
| `tenant_id`, `finding_id` or `task_id` | exactly one item (`CHECK num_nonnulls(finding_id, task_id) = 1`); composite foreign keys `(tenant_id, finding_id)` and `(tenant_id, task_id)` with `ON DELETE CASCADE`, so a row can never point at another tenant's item |
| `user_id` | the watcher (`ON DELETE CASCADE`) |
| `state` | `subscribed` or `unsubscribed`. An unsubscribe is a row, so later participation cannot override it |
| `reason` | `manual` (the bell), `added` (someone added them), `assigned`, `commented`, `status_changed`, `fix_claimed`, `mentioned`, `approval`, `created` |
| `added_by` | who added them (set when someone else did) |

Unique per tenant, item and user (two partial unique indexes). Rows hold ids only; no names or emails.

## Rules

- **Who can watch.** Anyone who can read the item may watch it themselves (a viewer included). Adding
  someone else needs `findings:assign` (finding) or `remediation:write` (task). The person added must
  be an active member of the tenant who can read the item now: a finding, through the data scope of
  the asset or the pentest campaign; a task, through at least one of its member findings in their data
  scope. Anyone else is refused with one generic answer (`this person cannot be added`), so the
  answer reveals neither who exists nor what they may see. The request is all or none.
- **Limits.** 50 subscribed watchers per item (checked in the same statement as the write), 10 people
  per request, a per-user rate limit on writes.
- **Reads fail closed.** The list re-checks every watcher's membership and read access. A watcher who
  left or lost scope is hidden (and not counted), the row is kept, so restored access restores
  watching.
- **Names.** Callers with `team:members:read` who are not pentest campaign clients see names, reasons
  and who added them, plus the owners of the finding's asset as context. Everyone else gets the count.
  Emails are never returned.
- **Taking part.** `Service.AutoWatch` inserts a `subscribed` row for a person who took part and never
  changes an existing row, so an explicit unsubscribe wins. It is for human actors only: the caller
  passes no user for scanners, the system, integrations or AI.
- **Leaving.** Offboarding deletes the member's rows in its transaction (`removed_watches` in the result
  and the audit entry); erasing personal data deletes any row left.

## API

| Method | Path | Gate |
|---|---|---|
| GET | `/api/v1/findings/{id}/participants` | `findings:read` + the finding in scope |
| PUT | `/api/v1/findings/{id}/subscription` | `findings:read` + scope (the caller's own choice) |
| POST | `/api/v1/findings/{id}/watchers` | `findings:assign` + scope |
| DELETE | `/api/v1/findings/{id}/watchers/{user_id}` | `findings:read`; removing someone else needs `findings:assign` |
| GET / PUT / POST / DELETE | `/api/v1/remediation/tasks/{task_id}/participants`, `/subscription`, `/watchers`, `/watchers/{user_id}` | `remediation:read`; adding, and removing others, `remediation:write` |

Adding or removing **another** person is audited (`work_item.watcher_added`, `work_item.watcher_removed`,
target user id in the metadata). A person's own bell and automatic rows are not (high volume, no
security weight).

## Code

`pkg/domain/participation` (types, repository interface), `internal/infra/postgres/work_item_subscription_repository.go`,
`internal/app/participation` (service), `internal/app/finding/participation_access.go` and
`internal/app/remediation/participation_access.go` (the read rules of each item kind, reused from the
services that read the items), `internal/infra/http/handler/participation_handler.go`,
`internal/infra/http/routes/participation.go`.
