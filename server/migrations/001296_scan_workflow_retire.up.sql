-- Deleting a scan workflow never deletes its run history (research/62 §5.1,
-- SW4). A workflow with runs is retired instead: it leaves the workflow list,
-- cannot be edited or run, and its runs keep their graph (the steps stay).
-- A workflow without runs is still deleted. scan_runs.scan_workflow_id moves
-- from ON DELETE CASCADE to NO ACTION (checked at the end of the statement, so
-- deleting a whole tenant still works), so no delete can cascade a
-- run away again.
--
-- The (tenant_id, name, version) uniqueness now holds among live workflows
-- only, so the name of a retired workflow can be used again.
--
-- expand-contract-ok: the unique constraint is replaced by an equivalent partial unique index created first; the FK is recreated without the cascade (no column change)

ALTER TABLE scan_workflows ADD COLUMN IF NOT EXISTS retired_at TIMESTAMPTZ;
COMMENT ON COLUMN scan_workflows.retired_at IS 'When the workflow was deleted while it had runs: hidden, read-only, kept for its run history.';

ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_scan_workflow_id_fkey;
ALTER TABLE scan_runs
    ADD CONSTRAINT scan_runs_scan_workflow_id_fkey
    FOREIGN KEY (scan_workflow_id) REFERENCES scan_workflows (id) ON DELETE NO ACTION NOT VALID;
ALTER TABLE scan_runs VALIDATE CONSTRAINT scan_runs_scan_workflow_id_fkey;

CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_workflows_live_name_version
    ON scan_workflows (tenant_id, name, version) WHERE retired_at IS NULL;
ALTER TABLE scan_workflows DROP CONSTRAINT IF EXISTS scan_workflows_name_version_unique;
