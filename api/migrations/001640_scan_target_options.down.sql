ALTER TABLE scans DROP CONSTRAINT IF EXISTS chk_scans_target_options_object;
ALTER TABLE scans DROP COLUMN IF EXISTS target_options;
