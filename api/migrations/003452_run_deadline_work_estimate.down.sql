-- A deadline moved by a claim reads as set by the workflow's timeout again.
UPDATE scan_runs SET deadline_reason = 'workflow_max_duration' WHERE deadline_reason = 'work_estimate';
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_deadline_reason;
ALTER TABLE scan_runs ADD CONSTRAINT chk_scan_runs_deadline_reason CHECK (deadline_reason IS NULL OR deadline_reason IN (
    'scan_max_duration', 'workflow_max_duration', 'platform_cap', 'legacy'));
