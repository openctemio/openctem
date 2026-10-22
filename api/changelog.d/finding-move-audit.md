### Security: every finding status move and assignment is in the audit log

- Each applied status move writes a `finding.status_changed` audit row (old and new status, closure reason and verification for a close, actor or system), whatever route made it: the status change, bulk status, fix claim, verify, reject, approvals, ticket webhooks and VEX. A bulk move adds one `finding.bulk_updated` summary row. Closing a critical, P0 or KEV finding is audited at high severity.
- Assigning and unassigning (single and bulk) write `finding.assigned` / `finding.unassigned` with the previous and new assignee.
- The end of a risk acceptance writes its audit row in the same transaction.
- Before, these moves were only on the finding timeline, which is deleted with the finding.
