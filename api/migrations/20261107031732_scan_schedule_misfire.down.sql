ALTER TABLE scans
    DROP COLUMN IF EXISTS last_missed_reason,
    DROP COLUMN IF EXISTS last_missed_at;
