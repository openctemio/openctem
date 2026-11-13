-- The deadline sweep of runs on AI workers reads the live worker runs every
-- minute (docs/architecture/ai-analysis.md); this keeps it off the rest of
-- the run ledger. Schema only.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ai_runs_worker_live ON ai_runs (deadline_at)
    WHERE executor IN ('platform_worker', 'tenant_worker') AND status IN ('queued', 'running', 'waiting_tool', 'waiting_approval');
