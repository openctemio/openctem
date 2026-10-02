-- Add CHECK constraints for scope validation bounds

-- Priority must be between 1 and 10 (0 is default/unset)
DO $$ BEGIN
    ALTER TABLE scope_targets ADD CONSTRAINT chk_scope_target_priority
        CHECK (priority >= 0 AND priority <= 10);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Interval hours must be between 1 and 8760 (max 1 year), 0 means unset
DO $$ BEGIN
    ALTER TABLE scan_schedules ADD CONSTRAINT chk_scan_schedule_interval
        CHECK (interval_hours >= 0 AND interval_hours <= 8760);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
