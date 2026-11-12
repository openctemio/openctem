-- A scan's run summary comes from its runs, and a refused trigger is a run.
--
-- 1. pipeline_runs.status gains 'blocked': a trigger refused before anything
--    was dispatched (scope gate, freeze window, unavailable tool or sensor, no
--    target). refusal_code holds the refusal's code; error_message its text.
-- 2. scans.blocked_runs counts them.
-- 3. Every scan's last_run_id/last_run_at/last_run_status and run counters are
--    recomputed from its runs (the statement the API now runs after every run
--    change, internal/infra/postgres/scan_run_summary.go). Before, a refused
--    scheduled trigger moved last_run_at with no run behind it and runs were
--    counted only when they finished, so a scan could read "Last run: today"
--    beside "Runs: 0".
--
-- Safe on populated tables: the new constraint is added NOT VALID and then
-- validated (no long exclusive lock); the new columns are nullable or have a
-- default; the backfill touches only the scan summary columns.

ALTER TABLE pipeline_runs DROP CONSTRAINT IF EXISTS chk_pipeline_runs_status;
ALTER TABLE pipeline_runs ADD CONSTRAINT chk_pipeline_runs_status CHECK (
    status IN ('pending', 'running', 'completed', 'partial', 'failed', 'canceled', 'timeout', 'blocked')
) NOT VALID;
ALTER TABLE pipeline_runs VALIDATE CONSTRAINT chk_pipeline_runs_status;

ALTER TABLE pipeline_runs ADD COLUMN IF NOT EXISTS refusal_code VARCHAR(64);
COMMENT ON COLUMN pipeline_runs.refusal_code IS
    'Why a blocked run was refused (the domain error code, e.g. ALL_TARGETS_EXCLUDED); NULL for other runs';

ALTER TABLE scans ADD COLUMN IF NOT EXISTS blocked_runs INTEGER NOT NULL DEFAULT 0;

UPDATE scans s
SET (last_run_id, last_run_at, last_run_status,
     total_runs, successful_runs, failed_runs, partial_runs, blocked_runs) = (
    SELECT l.id, l.created_at, l.status,
           a.total, a.successful, a.failed, a.partial, a.blocked
    FROM (
        SELECT COUNT(*)::int AS total,
               (COUNT(*) FILTER (WHERE pr.status = 'completed'))::int AS successful,
               (COUNT(*) FILTER (WHERE pr.status IN ('failed', 'timeout')))::int AS failed,
               (COUNT(*) FILTER (WHERE pr.status = 'partial'))::int AS partial,
               (COUNT(*) FILTER (WHERE pr.status = 'blocked'))::int AS blocked
        FROM pipeline_runs pr
        WHERE pr.tenant_id = s.tenant_id AND pr.scan_id = s.id
    ) a
    LEFT JOIN LATERAL (
        SELECT pr.id, pr.created_at, pr.status
        FROM pipeline_runs pr
        WHERE pr.tenant_id = s.tenant_id AND pr.scan_id = s.id
        ORDER BY pr.created_at DESC, pr.id DESC
        LIMIT 1
    ) l ON true
);
