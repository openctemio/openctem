-- Asset coverage planner (docs/rfcs/RFC-093-asset-coverage.md): the planner
-- now also picks covered pairs whose cadence has elapsed and blocked pairs
-- whose recheck time has passed, per tenant and capability, oldest first.
-- The old partial index covered due and failed rows per tenant only.
--
-- Live impact (2026-10-25): ~1.4 k ledger rows, a sub-second build; the
-- index is built in the migration's transaction (no CONCURRENTLY).

DROP INDEX IF EXISTS idx_asset_coverage_due;

CREATE INDEX IF NOT EXISTS idx_asset_coverage_plannable
    ON asset_coverage (tenant_id, capability, next_due_at)
    WHERE state IN ('due', 'failed', 'covered', 'blocked');
