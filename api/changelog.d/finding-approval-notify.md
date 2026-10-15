### Added: approvers are told about finding false-positive and accepted-risk requests, with reminders

- A new request (from a person or an AI triage proposal) notifies the members
  who may decide it, in-app (notification type `finding_approval`) and by
  email: owners, admins and roles holding `findings:approve`, whose data scope
  holds the finding. The requester is never notified as an approver, and an
  approver outside the finding's data scope is not told.
- The email carries the finding title, the requested status and the dates,
  never the justification; its link opens the approvals inbox (sign-in
  required).
- `POST /api/v1/approvals/{id}/remind` (`findings:write`, the finding in the
  caller's data scope) reminds the same approvers, at most once an hour per
  request (409 otherwise), audited as `finding_approval.reminded`.
- Migration `002304` (`finding_approval_reminded_at`): a nullable column.
- VEX-created requests (batch, per scan report) are not notified one by one
  yet.
