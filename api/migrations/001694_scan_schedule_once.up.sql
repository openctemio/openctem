-- One-off scheduled scans: schedule_type 'once' runs once at schedule_run_at.
-- The wizard's "schedule for later, once" used to save a manual scan that
-- never ran.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS schedule_run_at TIMESTAMPTZ;

ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_schedule_type;
ALTER TABLE scans ADD CONSTRAINT chk_scans_schedule_type CHECK (
    schedule_type IN ('manual', 'daily', 'weekly', 'monthly', 'crontab', 'rrule', 'once')
);

-- A once schedule always names its run.
ALTER TABLE scans ADD CONSTRAINT chk_scans_once_run_at CHECK (
    schedule_type <> 'once' OR schedule_run_at IS NOT NULL
);
