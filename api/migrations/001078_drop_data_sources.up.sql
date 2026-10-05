-- expand-contract-ok: contract step; no released code reads or writes data_sources or assets.source_id / source_ref, and the asset-source priority settings API goes in the same change.
-- Retire RFC-003 (asset source priority): drop data_sources (legacy cleanup).
--
-- data_sources was the registry RFC-003 keyed its per-tenant priority and
-- trust-level settings on. Nothing ever wrote a row (0 on the production
-- restore) and no ingest path consulted the priority gate, so the settings
-- API configured a no-op. RFC-003 is withdrawn: provenance lives on the
-- asset (discovery_source, discovery_tool) and on findings (source,
-- ingest_channel); the per-source layer RFC-042 plans gets its own
-- tenant-scoped table when it is built.
--
-- Dropped:
--   * data_sources (0 rows) and its enum source_status;
--   * assets.source_id (FK to data_sources) and assets.source_ref: 0 non-null
--     values, never written or read by code;
--   * the 'asset_source' key in tenants.settings (one tenant, value {}).
-- Kept: the enum source_type (findings.ingest_channel uses it) and
-- assets.source_type (the sensor-rename upgrade check and 000230 read it).
--
-- Tenant isolation: unchanged. The table takes its own (shadow) RLS policy
-- with it. The settings rewrite removes one empty key and touches no other
-- part of tenants.settings.

-- finding_data_sources is dropped by drop_rule_management_tables; drop its foreign key here too so
-- this migration does not depend on the order the two land in.
ALTER TABLE IF EXISTS finding_data_sources DROP CONSTRAINT IF EXISTS finding_data_sources_source_id_fkey;
ALTER TABLE IF EXISTS asset_sources DROP CONSTRAINT IF EXISTS asset_sources_source_id_fkey;

ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_source_id_fkey;
DROP INDEX IF EXISTS idx_assets_source_id;
ALTER TABLE assets
    DROP COLUMN IF EXISTS source_id,
    DROP COLUMN IF EXISTS source_ref;

DROP TABLE IF EXISTS data_sources;
DROP TYPE IF EXISTS source_status;

UPDATE tenants SET settings = settings - 'asset_source'
WHERE settings ? 'asset_source';
