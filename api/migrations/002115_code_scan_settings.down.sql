ALTER TABLE repository_branches
    DROP CONSTRAINT IF EXISTS chk_repository_branches_full_scan_trigger,
    DROP CONSTRAINT IF EXISTS chk_repository_branches_baseline_state,
    DROP COLUMN IF EXISTS last_full_scan_trigger,
    DROP COLUMN IF EXISTS last_full_scan_at,
    DROP COLUMN IF EXISTS baseline_error,
    DROP COLUMN IF EXISTS baseline_at,
    DROP COLUMN IF EXISTS baseline_commit,
    DROP COLUMN IF EXISTS baseline_state;

DROP TABLE IF EXISTS code_scan_settings;
