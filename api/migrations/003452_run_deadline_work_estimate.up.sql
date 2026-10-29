-- A run's deadline counts active work, not queue wait
-- (docs/architecture/scan-lifecycle.md, "Deadline"): a claim may move it to the time the
-- claimed work needs, recorded as 'work_estimate'. Only the CHECK changes;
-- no row is rewritten (a constraint swap on scan_runs, no table rewrite).
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_deadline_reason;
ALTER TABLE scan_runs ADD CONSTRAINT chk_scan_runs_deadline_reason CHECK (deadline_reason IS NULL OR deadline_reason IN (
    'scan_max_duration', 'workflow_max_duration', 'platform_cap', 'legacy', 'work_estimate')) NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT chk_scan_runs_deadline_reason;
