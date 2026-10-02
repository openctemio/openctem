-- Drop scope validation constraints
ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS chk_scope_target_priority;
ALTER TABLE scan_schedules DROP CONSTRAINT IF EXISTS chk_scan_schedule_interval;
