### Security: finding comments are append-only, and ticket unlink needs the same permission as link

- Editing a finding comment keeps the original and appends a revision entry with the previous text; deleting one leaves a "deleted a comment" placeholder and keeps the original entries, whose text the activity feed then withholds. Both are audited (`finding.comment_edited`, `finding.comment_deleted`) before the change is made.
- A comment written by the requester, approver or rejecter of an approval request while it was open (or up to its decision) can no longer be edited or deleted (403), also after an accepted risk's period has ended.
- An edit or delete with no resolvable actor is refused (403) instead of skipping the author check.
- `DELETE /api/v1/findings/{id}/ticket-links/{link_id}` now needs `findings:fix_apply` in addition to `findings:write`, as linking does.
- **Behaviour change:** the activities endpoint no longer drops the entry of a deleted comment; it returns `comment_deleted` entries and marks the comment's earlier entries `deleted: true` without text.
