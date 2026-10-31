### Security: tenant-scoped deletes, audit diffs for scan profiles, ingest warning

- Deleting or changing a tenant tool configuration, reading one by id, and deleting an integration now filter on the organization in the same statement (they filtered on the id alone, with the callers checking the organization first). Defense in depth; no behaviour change for valid requests.
- Updating a scan profile, changing its quality gate, or setting it as the default now records what changed (field-level before and after) in the audit log, not only that it happened.
- Ingest logs a warning with the organization id when it cannot load the organization, instead of silently using the default identity and reconciliation rules.
- The web shell no longer polls the support-access banner for people without team:read (a 403 on every page).
