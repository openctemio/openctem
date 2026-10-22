# Finding comments are append-only

A comment on a finding is part of the record: the justification beside a
false-positive, acceptance or severity decision must not be rewritable after
the fact. Comments therefore keep their history.

## Behaviour

- **Create** writes the comment row and a `comment_added` activity (the
  original text).
- **Edit** (`PUT /api/v1/findings/{id}/comments/{comment_id}`) updates the
  comment's current text, appends a `comment_updated` activity holding the new
  text and `previous_content`, and writes the audit event
  `finding.comment_edited`. The `comment_added` entry and earlier revisions are
  never changed.
- **Delete** (`DELETE .../comments/{comment_id}`) removes the comment from the
  comment list, appends a `comment_deleted` activity (the tombstone) and writes
  `finding.comment_deleted`. Nothing is removed from the activity trail. The
  activities endpoint hides the text of a deleted comment's `comment_added` and
  `comment_updated` entries and marks them `deleted: true`; the feed shows
  "deleted a comment" in its place.
- The audit event is written **before** the change; if it cannot be written the
  edit or delete is refused (fail closed).
- Only the author can edit or delete. An unknown actor (no resolvable local
  user id) is refused with 403 rather than treated as allowed.
- **Decision lock.** A comment written by a participant of an approval request
  (its requester, approver or rejecter) while that request was open, or up to
  the moment it was approved or rejected, is locked: edit and delete return 403.
  A request that was canceled or expired decided nothing and locks nothing.
  There is no link column between comments and approvals; the lock is derived
  from the finding's approval history, so it needs no migration.
- Status-change comments stay immutable, as before.

## Pentest campaign clients

A client sees `comment_updated` and `comment_deleted` entries only for
comments that were visible to the client, and only the current text, never
`previous_content`.

## Ticket links

Unlinking a ticket (`DELETE /api/v1/findings/{id}/ticket-links/{link_id}`)
needs `findings:write` and `findings:fix_apply`, the same as linking.

## Threat model

| Threat | Control |
|---|---|
| A requester or approver rewrites or deletes the reason after the decision | Decision lock, revisions, tombstone |
| A deleted comment's text lingers in the feed | Read-time placeholder for every entry of that comment |
| An edit or delete leaves no trace | Audit event before the change, plus the activity entries |
| Anonymous or machine actor edits a user's comment | Empty actor is refused |
| Cross-tenant or out-of-scope comment id | Unchanged: tenant-scoped lookup, finding scope check |
