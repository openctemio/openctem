### Added: transfer ownership of an organization

- The owner can hand the organization to an existing member: `POST /api/v1/organization/ownership-transfer` (owner, step-up). The member must be an active person with two-factor authentication on and not managed by another organization; an outside member nobody manages becomes internal after the owner confirms it. The owner chooses what they become (administrator by default, or member or viewer).
- The member accepts with their own step-up within 72 hours (`POST .../approve`) or declines (`POST .../reject`); the owner can cancel (`DELETE`). Acceptance re-checks everything in one transaction and ends with exactly one owner. Both people are emailed at each step; the audit log records the request, the transfer (critical), cancellations and declines.
- The error for changing the owner's role now points to Transfer ownership.
- Migration `002206` adds the `tenant_ownership_transfers` table (new and empty; no operator step).
