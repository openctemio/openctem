-- A scan run an automation step started is recorded as such (research/62
-- P0-11): trigger_type 'automation' (before, these runs said 'manual').
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_trigger_type;
ALTER TABLE scan_runs
    ADD CONSTRAINT chk_scan_runs_trigger_type
    CHECK (trigger_type IN ('manual', 'schedule', 'webhook', 'api', 'on_asset_discovery', 'system', 'automation')) NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT chk_scan_runs_trigger_type;

-- Runs an automation started before this migration carry the automation in
-- triggered_by ('workflow:<id>'); they are relabelled.
UPDATE scan_runs SET trigger_type = 'automation'
WHERE triggered_by LIKE 'workflow:%' AND trigger_type = 'manual';
