### Added: bootstrap-admin creates the first organization

- `bootstrap-admin` creates the first organization: `-org-name`,
  `-org-slug` (derived when empty), `-org-owner-email`, `-org-owner-name`
  (env `ORG_NAME`, `ORG_SLUG`, `ORG_OWNER_EMAIL`, `ORG_OWNER_NAME`). It uses
  the console's organization service (audited `tenant.created` and
  `user.created`); a new owner gets a one-time set-password link, emailed
  with SMTP or printed once. Re-running skips an existing organization.
- `create-first-team` (self-service mode) is audited as `tenant.created` and
  writes the organization and its owner in one transaction.
