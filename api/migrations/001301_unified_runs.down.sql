-- Reverses 001295. Runs that execute no scan workflow (retest and other
-- non-scan kinds) cannot exist without one, so they are deleted first; their
-- step runs go with them (ON DELETE CASCADE) and their commands keep running
-- unlinked (ON DELETE SET NULL).
DROP INDEX IF EXISTS idx_finding_retests_run;
ALTER TABLE finding_retests DROP CONSTRAINT IF EXISTS fk_finding_retests_run;
ALTER TABLE finding_retests DROP COLUMN IF EXISTS run_id;

DELETE FROM scan_runs WHERE scan_workflow_id IS NULL;
UPDATE scan_runs SET trigger_type = 'api' WHERE trigger_type = 'system';

ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_trigger_type;
ALTER TABLE scan_runs
    ADD CONSTRAINT chk_scan_runs_trigger_type
    CHECK (trigger_type IN ('manual', 'schedule', 'webhook', 'api', 'on_asset_discovery'));

DROP INDEX IF EXISTS idx_scan_runs_tenant_kind_created;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_workflow_kind;
ALTER TABLE scan_runs ALTER COLUMN scan_workflow_id SET NOT NULL;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_subject;
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_kind;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS subject;
ALTER TABLE scan_runs DROP COLUMN IF EXISTS kind;
