-- Asset Lifecycle Management — stale detection tier.
--
-- Adds the 'stale' status to assets.status, plus two new columns
-- driving the lifecycle worker's decisions: lifecycle_paused_until
-- (per-asset snooze) and manual_status_override (operator-takes-
-- control flag). A partial index on (tenant_id, status, last_seen_at)
-- keeps the worker's daily query fast even on 10M-row deployments.
--
-- Backward-compatibility promise: an asset with both new columns
-- NULL / false is indistinguishable from the pre-migration asset,
-- so enabling this migration alone does NOT flip any asset to stale.
-- The worker additionally refuses to run unless the tenant opts in
-- via tenant.settings.asset_lifecycle.enabled.

BEGIN;

-- 1. Extend the status CHECK to allow the new 'stale' value. The
--    previous constraint enumerated the three older states; we drop
--    and recreate since Postgres cannot ALTER a CHECK in place.
ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_status;
ALTER TABLE assets ADD CONSTRAINT chk_assets_status
    CHECK (status IN ('active', 'stale', 'inactive', 'archived'));

-- 2. Per-asset lifecycle pause. NULL = no pause; the worker treats
--    this column as "if >= NOW(), skip me". Stored as TIMESTAMPTZ
--    so clock-skew between cron and DB row cannot produce stale
--    logic.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS lifecycle_paused_until TIMESTAMPTZ;

-- 3. Manual status override — when true, the worker is not allowed
--    to write to this row's status. Operator-owned.
ALTER TABLE assets ADD COLUMN IF NOT EXISTS manual_status_override BOOLEAN NOT NULL DEFAULT FALSE;

-- 4. Index the hot query. Worker selects:
--      WHERE tenant_id = ? AND status IN ('active', 'stale')
--        AND manual_status_override = false
--        AND (lifecycle_paused_until IS NULL OR lifecycle_paused_until < NOW())
--        AND last_seen_at < NOW() - INTERVAL 'N days'
--    The partial index covers the first two clauses which have high
--    selectivity; the time comparison is a cheap seq-filter on a
--    small candidate set.
--
--    CONCURRENTLY so a large assets table does not block writes
--    during migration. The IF NOT EXISTS lets re-running the
--    migration (or a pre-existing index in some environments) pass
--    cleanly.
COMMIT;

-- 5. Index creation must live outside the transaction because
--    CREATE INDEX CONCURRENTLY refuses to run inside one. The
--    migration framework will stop here and run the next block in
--    its own transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_lifecycle_candidates
    ON assets (tenant_id, status, last_seen_at)
    WHERE status IN ('active', 'stale') AND manual_status_override = false;

-- 6. Column comments — help operators greping the schema understand
--    what they do without hunting through code.
COMMENT ON COLUMN assets.lifecycle_paused_until IS
    'If NOW() < this value, the lifecycle worker skips this asset (operator snooze).';
COMMENT ON COLUMN assets.manual_status_override IS
    'When TRUE, the lifecycle worker never writes to assets.status for this row.';
