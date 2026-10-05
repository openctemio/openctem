### Removed: the bootstrap-tenant command

- `bootstrap-tenant` (raw SQL, unaudited, ignored `TENANT_CREATION_MODE`) is
  no longer built or shipped in the image. Use
  `bootstrap-admin -org-name … -org-owner-email …`.
- `sla.Service.CreateDefaultTenantPolicy`, which nothing called.
