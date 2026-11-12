-- A run's deadline is policy, not a default (research/122, RFC-046 §6.3
-- amendment): a scan has a max duration only when its owner set one, and
-- every run records which policy set its deadline.
--
-- scans.timeout_seconds lost its column default of 3600, which every scan
-- created without a choice carried; those rows are indistinguishable from a
-- chosen 1 h, so 3600 becomes NULL (no max duration: the platform's 24 h cap
-- applies, and the commands' leases keep a slow but alive run going). Any
-- other value stays as the owner's cap.
--
-- Live impact: one UPDATE on scans (small table) and a nullable column on
-- scan_runs (no rewrite). Runs in flight keep the deadline written when they
-- started; their reason is backfilled as 'legacy'.

ALTER TABLE scans ALTER COLUMN timeout_seconds DROP NOT NULL;
ALTER TABLE scans ALTER COLUMN timeout_seconds DROP DEFAULT;
UPDATE scans SET timeout_seconds = NULL WHERE timeout_seconds = 3600;

ALTER TABLE scan_runs ADD COLUMN deadline_reason TEXT;
ALTER TABLE scan_runs ADD CONSTRAINT chk_scan_runs_deadline_reason CHECK (deadline_reason IS NULL OR deadline_reason IN (
    'scan_max_duration', 'workflow_max_duration', 'platform_cap', 'legacy'));
UPDATE scan_runs SET deadline_reason = 'legacy' WHERE deadline_at IS NOT NULL;
