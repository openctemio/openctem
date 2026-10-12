-- Every unit of sensor work belongs to a run the user can find (research/62
-- P0-3, SW1). A scan run gets a kind; a run that does not execute a scan
-- workflow (a finding retest today; CTEM validation, connector and system
-- work next) has no scan_workflow_id and names what it is about in subject.
--
--   kind     scan | quick | retest | validation | test | connector | system
--   subject  {"finding_id": ..., "retest_id": ...} for a retest
--
-- finding_retests.run_id links a retest to its run (tenant-composite foreign
-- key: a retest can only point at a run of its own tenant). Existing rows are
-- kind 'scan'. All columns are added with defaults or as nullable: the
-- statements take a brief lock and rewrite nothing.

ALTER TABLE scan_runs
    ADD COLUMN IF NOT EXISTS kind VARCHAR(20) NOT NULL DEFAULT 'scan',
    ADD COLUMN IF NOT EXISTS subject JSONB;

ALTER TABLE scan_runs
    ADD CONSTRAINT chk_scan_runs_kind
    CHECK (kind IN ('scan', 'quick', 'retest', 'validation', 'test', 'connector', 'system')) NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT chk_scan_runs_kind;

ALTER TABLE scan_runs
    ADD CONSTRAINT chk_scan_runs_subject
    CHECK (subject IS NULL OR jsonb_typeof(subject) = 'object') NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT chk_scan_runs_subject;

-- A run of kind 'scan' or 'quick' executes a scan workflow; the others may not.
ALTER TABLE scan_runs ALTER COLUMN scan_workflow_id DROP NOT NULL;
ALTER TABLE scan_runs
    ADD CONSTRAINT chk_scan_runs_workflow_kind
    CHECK (scan_workflow_id IS NOT NULL OR kind NOT IN ('scan', 'quick', 'test')) NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT chk_scan_runs_workflow_kind;

-- Platform-started work (an automatic retest, a system job) is triggered by
-- the system, not by a person, a schedule or an API key.
ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS chk_scan_runs_trigger_type;
ALTER TABLE scan_runs
    ADD CONSTRAINT chk_scan_runs_trigger_type
    CHECK (trigger_type IN ('manual', 'schedule', 'webhook', 'api', 'on_asset_discovery', 'system')) NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT chk_scan_runs_trigger_type;

CREATE INDEX IF NOT EXISTS idx_scan_runs_tenant_kind_created
    ON scan_runs (tenant_id, kind, created_at DESC);

ALTER TABLE finding_retests ADD COLUMN IF NOT EXISTS run_id UUID;
ALTER TABLE finding_retests
    ADD CONSTRAINT fk_finding_retests_run
    FOREIGN KEY (tenant_id, run_id) REFERENCES scan_runs (tenant_id, id) ON DELETE SET NULL (run_id) NOT VALID;
ALTER TABLE finding_retests VALIDATE CONSTRAINT fk_finding_retests_run;
CREATE INDEX IF NOT EXISTS idx_finding_retests_run ON finding_retests (run_id) WHERE run_id IS NOT NULL;

COMMENT ON COLUMN scan_runs.kind IS 'What the run is: scan, quick, retest, validation, test, connector or system (system runs are hidden from the Runs list by default).';
COMMENT ON COLUMN scan_runs.subject IS 'What a run that executes no scan workflow is about, e.g. {"finding_id": ..., "retest_id": ...}.';
COMMENT ON COLUMN finding_retests.run_id IS 'The scan run (kind retest) that holds this retest''s commands, logs and timeline.';
