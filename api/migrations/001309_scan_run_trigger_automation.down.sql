UPDATE scan_runs SET trigger_type = 'manual' WHERE trigger_type = 'automation';
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_trigger_type;
ALTER TABLE scan_runs
    ADD CONSTRAINT chk_scan_runs_trigger_type
    CHECK (trigger_type IN ('manual', 'schedule', 'webhook', 'api', 'on_asset_discovery', 'system')) NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT chk_scan_runs_trigger_type;
