### Security: people outside an organization join as limited, expiring external members

- A member whose email domain the organization does not hold (another company's, a personal address, or an unverified work domain) is now an **external member** (RFC-058):
  - they join only by accepting an invitation, as a viewer with no data scope;
  - they can never be an owner (database-enforced), an administrator, or hold a full-data-access role;
  - without a home organization their access must end (90 days by default, 365 at most);
  - expired access is suspended automatically within a minute, in that organization only.
- Administrators set a new end date with `PATCH /api/v1/organization/members/{member_id}/access`. The members list shows `kind`, `home_organization`, `access_expires_at` and `suspended_reason`.
- Existing memberships are unchanged (all internal).
- An organization that has not verified any domain keeps treating colleagues on its own unclaimed domain as internal.
- Migration 001310.
