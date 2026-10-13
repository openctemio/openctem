ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_deadline_reason;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS deadline_reason;

UPDATE scans SET timeout_seconds = 3600 WHERE timeout_seconds IS NULL;
ALTER TABLE scans ALTER COLUMN timeout_seconds SET DEFAULT 3600;
ALTER TABLE scans ALTER COLUMN timeout_seconds SET NOT NULL;
