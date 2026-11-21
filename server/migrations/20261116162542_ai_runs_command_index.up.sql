-- The run of an AI analysis job, found by its command: the commands list and
-- a command's logs show the job's payload only to a caller who may read the
-- run's finding (docs/architecture/ai-analysis.md). Partial: only worker runs
-- have a command.
--
-- Live impact: built CONCURRENTLY (no write lock on ai_runs); the only
-- statement in this file because CONCURRENTLY cannot run inside a transaction.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ai_runs_command ON ai_runs (command_id) WHERE command_id IS NOT NULL;
