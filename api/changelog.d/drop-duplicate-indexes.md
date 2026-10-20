### Changed: six duplicate database indexes are dropped, so findings, integrations and change events write less

- `findings` no longer maintains `idx_findings_tenant_id_pk` and `ux_findings_id_tenant`, `integrations` no longer maintains `idx_integrations_tenant_id_pk`, `groups` and `remediation_campaigns` drop their repeated `(tenant_id, id)` unique constraint, and `asset_change_events` drops `idx_asset_change_events_tenant` (the primary key serves the same reads backwards). Every one repeated an index that stays.
- The foreign keys that were bound to a dropped unique index are re-created unchanged and validated, bound to the surviving index. No rows change.
- **Upgrade note:** the migration takes a short exclusive lock on `findings`, `groups` and `remediation_campaigns` (5 s lock timeout) while the dependent keys are re-added; run it outside a bulk ingest.
