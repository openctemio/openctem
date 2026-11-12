-- One-off schedules become manual (their run, if still ahead, is dropped).
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_once_run_at;
UPDATE scans SET schedule_type = 'manual', next_run_at = NULL WHERE schedule_type = 'once';

ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_schedule_type;
ALTER TABLE scans ADD CONSTRAINT chk_scans_schedule_type CHECK (
    schedule_type IN ('manual', 'daily', 'weekly', 'monthly', 'crontab', 'rrule')
);

ALTER TABLE scans DROP COLUMN IF EXISTS schedule_run_at;
