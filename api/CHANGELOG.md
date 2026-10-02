# Changelog

Notable changes to the OpenCTEM API. Release notes for each version are
published at https://docs.openctem.io (operations/release-notes-*).

## Unreleased

### Changed (behaviour change)

- **Organizations are created by the platform administrator by default.**
  `TENANT_CREATION_MODE` now defaults to `admin_only` (was `self_service`).
  Signed-in users can no longer create organizations themselves
  (`POST /api/v1/auth/create-first-team` and `POST /api/v1/tenants` return
  403); the administrator creates them in the console or with
  `bootstrap-admin -org-*`. Existing organizations and memberships are
  unaffected. To keep self-service creation (SaaS or trial installs), set
  `TENANT_CREATION_MODE=self_service` (Helm: `api.tenantCreationMode=self_service`).
  Any value other than `self_service` is treated as admin-only.

### Added

- `bootstrap-admin` creates the first organization: `-org-name`,
  `-org-slug` (derived when empty), `-org-owner-email`, `-org-owner-name`
  (env `ORG_NAME`, `ORG_SLUG`, `ORG_OWNER_EMAIL`, `ORG_OWNER_NAME`). It uses
  the console's organization service (audited `tenant.created` and
  `user.created`); a new owner gets a one-time set-password link, emailed
  with SMTP or printed once. Re-running skips an existing organization.
- `create-first-team` (self-service mode) is audited as `tenant.created` and
  writes the organization and its owner in one transaction.

### Removed

- `bootstrap-tenant` (raw SQL, unaudited, ignored `TENANT_CREATION_MODE`) is
  no longer built or shipped in the image. Use
  `bootstrap-admin -org-name … -org-owner-email …`.
- `sla.Service.CreateDefaultTenantPolicy`, which nothing called.
