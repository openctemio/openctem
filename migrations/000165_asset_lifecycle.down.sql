-- Roll back the stale-detection lifecycle migration. Any assets
-- currently in the 'stale' status have to be demoted back to
-- 'active' before the CHECK can be tightened — otherwise the
-- constraint re-creation fails.

BEGIN;

-- Demote any stale assets to active. Preserves the row, loses the
-- stale marker. Deliberate: losing "was flagged stale" is fine on
-- rollback because the feature is off afterward.
UPDATE assets SET status = 'active' WHERE status = 'stale';

-- Drop columns.
ALTER TABLE assets DROP COLUMN IF EXISTS lifecycle_paused_until;
ALTER TABLE assets DROP COLUMN IF EXISTS manual_status_override;

-- Restore the original status CHECK.
ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_status;
ALTER TABLE assets ADD CONSTRAINT chk_assets_status
    CHECK (status IN ('active', 'inactive', 'archived'));

COMMIT;

-- Drop the worker index. Outside the transaction to mirror the up
-- migration's CONCURRENTLY pattern.
DROP INDEX CONCURRENTLY IF EXISTS idx_assets_lifecycle_candidates;
