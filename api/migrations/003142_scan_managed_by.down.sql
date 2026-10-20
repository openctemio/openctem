DROP INDEX IF EXISTS scans_managed_key;
ALTER TABLE scans
    DROP CONSTRAINT IF EXISTS scans_managed_by_check,
    DROP COLUMN IF EXISTS managed_key,
    DROP COLUMN IF EXISTS managed_by;
