-- RFC-046 D11 (P1.5): a scan schedule may be an RFC 5545 recurrence rule
-- (RRULE parts, e.g. FREQ=WEEKLY;BYDAY=MO;BYHOUR=2), evaluated in the scan
-- timezone. The API validates the rule (it parses, has a future occurrence,
-- never fires more often than every 15 minutes); the column only bounds it.
-- Additive: existing daily/weekly/monthly/crontab schedules are unchanged.
ALTER TABLE scans ADD COLUMN IF NOT EXISTS schedule_rrule TEXT;

ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_schedule_rrule;
ALTER TABLE scans ADD CONSTRAINT chk_scans_schedule_rrule
    CHECK (schedule_rrule IS NULL OR length(schedule_rrule) BETWEEN 1 AND 500);

ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_schedule_type;
ALTER TABLE scans ADD CONSTRAINT chk_scans_schedule_type
    CHECK (schedule_type IN ('manual', 'daily', 'weekly', 'monthly', 'crontab', 'rrule'));
