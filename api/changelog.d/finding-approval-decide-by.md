### Fixed: finding approval requests have a decide-by time, one pending request per finding, and approve in one transaction

- A false-positive or accepted-risk request now has a decide-by time (14 days),
  separate from the end of the acceptance it asks for. A pending request past
  it can no longer be decided and the hourly approval expiration job marks it
  expired, with a timeline entry and an audit row (`finding_approval.expired`).
  Before, a pending request waited forever. The database enforces it too
  (approve and reject claim no row past it), and any writer that names no
  decide-by time (VEX and AI-triage requests) gets the 14-day default.
- A finding holds at most one pending request (from a person or a platform
  actor); a second request answers 409. Older duplicates are cancelled by a
  migration (newest pending request kept), with a timeline entry.
- Approving writes the request, the finding's status and the timeline entry in
  one transaction: two approvers at once cannot both apply it, and a failure
  leaves the request pending and the finding unchanged.
- A request can only be made for a finding inside the requester's data scope.
- The approval API returns `decide_by`.
- Migrations `002300`–`002303` (`finding_approval_decide_by`,
  `finding_approval_decide_by_backfill`, `finding_approval_pending_dedupe`,
  `finding_approval_one_pending`); safe on a populated table (the table is
  small; new column nullable, backfill touches pending rows only).
