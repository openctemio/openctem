-- =============================================================================
-- Migration 000381: drop assets.owner_id (contract step of 000340)
-- =============================================================================
-- expand-contract-ok: contract step of 000340 (#944); no code reads or writes assets.owner_id since then. Merge only after a release that contains #944.
-- 000340 copied every assets.owner_id into asset_owners (primary, source
-- owner_ref) and the application now reads and writes owners in asset_owners
-- only. Nothing reads the column any more (no view, function, policy or
-- application query), so it is dropped together with its two indexes and its
-- foreign key.
--
-- Live-database safety: DROP COLUMN only changes the catalog (no table
-- rewrite), but it needs a brief ACCESS EXCLUSIVE lock on assets. lock_timeout
-- makes the migration fail fast instead of queueing every asset query behind a
-- long-running transaction; re-run it when the database is quieter.
-- The down migration restores the column from the owner_ref rows.
-- =============================================================================

SET lock_timeout = '5s';

DROP INDEX IF EXISTS idx_assets_tenant_owner;
DROP INDEX IF EXISTS idx_assets_owner_id;
ALTER TABLE assets DROP COLUMN IF EXISTS owner_id;

RESET lock_timeout;
