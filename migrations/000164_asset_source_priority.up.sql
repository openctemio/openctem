-- RFC-003 Phase 1a — Asset Source Priority & Field Attribution.
-- Foundation migration. No data rewrite, no column drops, no
-- destructive changes. Tenants that do not opt in see zero behavior
-- change.
--
-- The config lives in tenants.settings.asset_source (JSONB), so no
-- schema changes are needed for the settings payload itself. This
-- migration adds one supporting index to keep the future ingest
-- priority gate (Phase 1b) cheap.
--
-- See: docs/architecture/asset-source-priority.md
--      docs/architecture/asset-source-priority-impl-plan.md

BEGIN;

-- Fast lookup for the primary source(s) of an asset. asset_sources
-- typically holds < 10 rows per asset, so a partial index on the
-- is_primary flag stays tiny while powering "which source owns this
-- asset?" queries without scanning every row.
--
-- CONCURRENTLY is not used here because we're inside a single
-- transaction; asset_sources is small enough that the lock window is
-- negligible. If that changes, split into a separate non-tx
-- migration with CREATE INDEX CONCURRENTLY.
CREATE INDEX IF NOT EXISTS idx_asset_sources_asset_primary
    ON asset_sources (asset_id)
    WHERE is_primary = true;

-- Documentation touch — settings.asset_source is a JSONB subtree we
-- now rely on. Keeping the comment adjacent to the migration that
-- introduced the contract helps future readers grep for it.
COMMENT ON COLUMN tenants.settings IS
    'Tenant settings JSONB. Includes asset_source{priority[], trust_levels{}, track_field_attribution} per RFC-003 from migration 000164.';

COMMIT;
