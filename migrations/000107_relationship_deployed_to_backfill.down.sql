-- =============================================================================
-- Migration 107 (down): no-op.
--
-- The forward migration was a one-shot data backfill that converted
-- bad `deployed_to` rows into `runs_on` (or deleted them when a
-- duplicate runs_on already existed). There is no safe way to roll
-- this back: the deleted rows are gone, and converting `runs_on` rows
-- back to `deployed_to` would re-introduce the bad data this migration
-- was written to fix.
--
-- If you need to revert specifically, restore from a pre-migration
-- backup. Re-running this down migration intentionally does nothing.
-- =============================================================================

SELECT 1;
