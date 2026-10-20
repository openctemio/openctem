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

## Who hears about a finding

Comments, status changes (a fix claim is one) and assignments go through one path
(`internal/app/finding/participation_notify.go`). `participation.Service.Recipients` decides, once, who hears:

1. The people the event is for by role (the assignee; the new assignee on an assignment, even if
   they had stopped watching) plus, when a **person** caused it, the watchers. A scanner, the system,
   an integration or an AI never adds watchers to the audience.
2. Minus the actor.
3. Minus whoever has an `unsubscribed` row (except the new assignee on an assignment).
4. Then only people who are, right now, active members who can read the finding (data scope, or the
   pentest campaign). Team-only content on a pentest finding (a team comment) never goes to a campaign
   client, watcher or not.

Each person gets one in-app notification (`audience = user`) with a `reason` (`assigned` for a role,
`watching` for a watcher). The inbox and live push keep applying the person's mutes, minimum severity
and the read-time scope filter. The notice carries the finding title and the event, never more than
before.

**Coalescing.** Events on one finding within 10 minutes fold into the person's unread notification of
the same type: the row takes the latest title, body and actor and its `coalesced_count` goes up. Once
read, the next event is a new notification.

**Taking part.** The author of a comment, the person who changes a status or claims a fix, the new
assignee, and the requester and the decider of an approval become watchers (reasons `commented`,
`status_changed`, `fix_claimed`, `assigned`, `approval`) through `AutoWatch`, unless they turned
**auto watch** off in their notification preferences (`auto_watch`, default on; `PUT
/api/v1/notifications/preferences`). An existing row is never touched, so a stop wins.

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

## Console

The finding's side panel (page and drawer) and the remediation task page show a **People** section
(`web/src/features/findings/components/detail/finding-people.tsx`,
`web/src/features/remediation-hub/components/task-people.tsx`, both on the shared
`features/shared/components/watchers-block.tsx`): the assignee or owner, the watchers with a reason chip
each, the owners of the finding's asset as context, an Add control (shown from the route's gate; the
picker lists only the members the API says can read the item) and the bell. Without the member list
permission (viewers, pentest clients) the section shows the count and the bell only. The person's own
switch for automatic watching is in Settings > Notifications.

## Code

`pkg/domain/participation` (types, repository interface), `internal/infra/postgres/work_item_subscription_repository.go`,
`internal/app/participation` (service), `internal/app/finding/participation_access.go` and
`internal/app/remediation/participation_access.go` (the read rules of each item kind, reused from the
services that read the items), `internal/infra/http/handler/participation_handler.go`,
`internal/infra/http/routes/participation.go`.
