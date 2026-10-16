### Security: a verified SSO domain decides what its claim does to accounts on it

- Owners set, per verified SSO domain (Settings > Domains, `PUT
  /api/v1/organization/settings/domains/{domain_id}/signup-policy`, owner + step-up, audited): who may
  join by domain (`off`, `approval`, `auto`, as viewer or member), whether the organization is shown
  to colleagues during onboarding, `sso_required` (password and social sign-up for addresses on the
  domain are refused with 403 `SSO_REQUIRED`, nothing written) and `block_new_workspaces` (accounts
  on the domain cannot create organizations), optionally for subdomains. Everything is off by
  default and stops at once when the claim lapses.
- Accounts already on the domain get one e-mail when the organization first manages it; nothing is
  moved or shown to the organization.
- Migration 002641 adds the columns to `verified_domains` (small table, constant defaults).
