### Security: approvals and bulk verify run the lifecycle for the approver, and write only fix_applied findings

- Approving a status request re-runs the organization's finding lifecycle with
  the approver as the actor; a move the lifecycle no longer allows, or that
  needs a permission the approver lacks, leaves the approval pending.
- Verify-by-filter and reject-fix-by-filter write only findings that are still
  `fix_applied`, so a finding that moved on since it was read is not
  overwritten.
