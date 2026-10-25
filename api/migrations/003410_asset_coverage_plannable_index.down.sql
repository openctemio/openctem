DROP INDEX IF EXISTS idx_asset_coverage_plannable;

CREATE INDEX IF NOT EXISTS idx_asset_coverage_due
    ON asset_coverage (tenant_id, next_due_at) WHERE state IN ('due', 'failed');
