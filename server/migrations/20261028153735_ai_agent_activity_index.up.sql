-- Per-run lookups of an AI agent's timeline rows (undo of a run, override
-- rate, per-owner metrics; docs/architecture/ai-analysis.md).
--
-- CONCURRENTLY keeps finding_activities writable while it builds; it cannot
-- run in a transaction, so this file holds exactly one statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_finding_activities_ai_run
    ON finding_activities (tenant_id, ((source_metadata->'ai'->>'run_id')))
    WHERE actor_type = 'ai';
