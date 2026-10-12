### Added: idle Free workspaces

- A Free organization that nobody signs in to is reminded at 60 days (email to its owners and admins), becomes read-only at 90 days (changes refused with 403 `WORKSPACE_READ_ONLY`, reads keep working), gets a final warning at 113 days and is due for deletion at 120 days, when the platform administrators are alerted. Nothing is deleted automatically. A sign-in by any member undoes it at once. Every step is audited.
- Platform administrators see the stage at `GET /api/v1/admin/tenants/{tenantId}/idle` and can exempt an organization with a reason (`PUT .../idle/exemption`, ops_admin+).
- Pro, Enterprise and organizations without a plan are never affected. Migration 001347 (new, empty table).
