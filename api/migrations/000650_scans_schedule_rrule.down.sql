-- A scan on an rrule schedule cannot keep it: it goes back to manual
-- (it stops running on a schedule) before the type is narrowed again.
UPDATE scans SET schedule_type = 'manual', next_run_at = NULL WHERE schedule_type = 'rrule';
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_schedule_type;
ALTER TABLE scans ADD CONSTRAINT chk_scans_schedule_type
    CHECK (schedule_type IN ('manual', 'daily', 'weekly', 'monthly', 'crontab'));
ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_schedule_rrule;
ALTER TABLE scans DROP COLUMN IF EXISTS schedule_rrule;
