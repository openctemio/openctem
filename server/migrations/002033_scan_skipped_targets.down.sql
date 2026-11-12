ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_skipped_targets_size;
ALTER TABLE scans DROP COLUMN IF EXISTS skipped_targets;
