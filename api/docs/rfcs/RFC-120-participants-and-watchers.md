# RFC-120: Participants and watchers on findings and remediation tasks

| | |
|---|---|
| Status | Accepted (2026-10-20). Delivered in small steps; what is built is described in `docs/architecture/participants-and-watchers.md` and `docs/architecture/notification-system.md` |
| Scope | api (`internal/app/finding`, `internal/app/remediation`, `internal/app/participation`, notifications, member offboarding), web (finding and task sidebars) |
| Related | RFC-111 (approval tiers and sign-off), `docs/architecture/participants-and-watchers.md`, `docs/architecture/notification-system.md`, `docs/architecture/finding-status-lifecycle.md` |

## 1. Problem

Today one person hears about a finding: its assignee. Commenters, the person who claimed a fix and the
requester of an approval never hear about later activity. Remediation tasks tell nobody when their owner
changes. A finding can be assigned to a member who cannot read it, so the assignment notice is hidden
by the inbox scope filter and the SLA ladder targets a person who cannot act. A member who leaves keeps
the tasks and campaigns they owned. The notification preference "Mentions" does nothing.

## 2. Decisions

1. **One accountable assignee.** A finding has one assignee (a user). A task has one owner (a user or a
   team). Several people on one task are a team owner plus watchers. No assignee arrays.
2. **Watchers.** One table, `work_item_subscriptions`, for findings and tasks. A row is `subscribed` or
   `unsubscribed` and carries a reason (manual, added, assigned, commented, status_changed, fix_claimed,
   mentioned, approval, created). People who take part are subscribed automatically; scanners, system,
   integration and AI actors never are. An existing row, subscribed or not, is never changed by
   automatic participation, so an explicit unsubscribe wins.
3. **Watching grants nothing.** Membership, data scope and pentest visibility are checked when someone is
   added, again for each notification at send time, and again when the inbox or a list is read. Removed
   members lose their rows in the offboarding transaction. Losing data scope hides rows (fail closed)
   without deleting them.
4. **Users only.** Watchers are active members. No team watchers, no email-only guests.
5. **Storage.** One table, one nullable foreign key per entity with `num_nonnulls(finding_id, task_id) = 1`,
   and tenant-composite foreign keys so no row can point across tenants. Assignee and reviewer stay work
   fields; they are not rows of this table.
6. **Recipients.** One function builds the recipients of every event (assignee, task owner, reviewer,
   requester, watchers, mentioned users), removes the actor and the unsubscribed, applies the per-type
   mutes, then filters in SQL by active membership, data scope and pentest viewer rule. The same predicate
   is shared with the inbox and the live push so the three cannot drift apart. One notification row per
   recipient (`audience = user`), never an audience of everyone or of a group.
7. **Coalescing.** One in-app notice per recipient, item and type per 10 minutes: the existing unread row
   is updated (count and latest actor) instead of a new row.
8. **Privacy.** Watcher names are shown to members who can read the member list and the item; viewers and
   pentest clients see a count. Watcher data never leaves the tenant: not in exports, integration
   payloads, tracker sync or AI context. No comment text in email.
9. **Limits.** 50 watchers per item, 10 people per request, a per-user rate limit on subscription writes.
   No plan gating.
10. **Asset owners** are context only (shown in the People section, reached by the SLA ladder), never
    watchers automatically.

## 3. Defects fixed first

| Id | Defect | Fix |
|---|---|---|
| B1 | A finding can be assigned to a member who cannot read it | The assignee must be an active member who can read the finding (data scope, pentest campaign); `GET /api/v1/findings/{id}/assignable` lists only such members, without emails; bulk assignment refuses such targets per finding |
| B2 | Changing a task owner notifies nobody; task notices skip the scope filter | Notify the new owner (the user, or the members of the team); task notices reach only members who can read at least one of the task's findings; a finding moved between tasks notifies both owners |
| B3 | Offboarding leaves tasks and campaigns owned by the removed member | Reassign open tasks and campaigns to the plan's target in the same transaction, audited |
| B4 | The requester of an FP, accepted-risk or severity request is not told of the decision | In-app notice to the requester on approve, reject or cancel (outcome and title, never the justification) |
| B5 | The "Mentions" preference does nothing | Hidden until mentions ship |

## 4. Data model

```sql
CREATE TABLE work_item_subscriptions (
  id         uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  finding_id uuid,
  task_id    uuid,
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  state      varchar(12) NOT NULL DEFAULT 'subscribed',
  reason     varchar(16) NOT NULL,
  added_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
-- one row per user and item; composite (tenant_id, finding_id|task_id) foreign keys with ON DELETE CASCADE
```

`notifications.reason` (nullable) says why a person got a notice (assigned, owner, watching, approval, ...).
`notification_preferences.auto_watch` (default true) stops automatic watching for one person.

## 5. API

| Method | Path | Gate |
|---|---|---|
| GET | `/api/v1/findings/{id}/assignable?q=` | `findings:assign` + the finding in the caller's scope |
| GET | `/api/v1/findings/{id}/participants` | `findings:read` + scope |
| PUT | `/api/v1/findings/{id}/subscription` | `findings:read` + scope (self) |
| POST | `/api/v1/findings/{id}/watchers` | `findings:assign` + scope |
| DELETE | `/api/v1/findings/{id}/watchers/{user_id}` | self, or `findings:assign` |
| GET/PUT/POST/DELETE | `/api/v1/remediation/tasks/{task_id}/participants`, `/subscription`, `/watchers`, `/watchers/{user_id}` | read: `remediation:read`; others: `remediation:write` |

A target that is not an active member who can read the item is refused with one generic message, so the
answer does not reveal who exists or what they can see.

## 6. Threat model

| Threat | Control |
|---|---|
| A watcher learns about a finding outside their scope | recipient SQL joins scope; inbox read filter; check when added |
| Cross-tenant watcher or id injection | composite foreign keys; tenant from the request context only; target must be an active member of that tenant |
| Task notices leak | `remediation_task` joins the read-time filter: at least one member finding in scope |
| A pentest client sees a team-only comment through watching | the pentest viewer rule applies to every recipient |
| Spam by bulk add | caps, rate limit, audit of adds, self-removal always allowed |
| Enumeration through the add endpoint or the picker | generic refusal; the picker lists names only and needs `findings:assign` |
| A removed member keeps receiving | offboarding deletes the rows; the recipient query requires an active membership |
| Personal data persists | rows hold ids only; erasure deletes them |

## 7. Out of scope

Several assignees, team watchers, email-only guests, participation that grants access, watcher sync to
trackers or chat, auto-watching asset owners, a notification-level hierarchy.
