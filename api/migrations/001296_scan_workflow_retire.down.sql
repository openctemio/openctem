-- A retired workflow keeps its runs; it is renamed apart so the uniqueness
-- over every row can come back.
UPDATE scan_workflows
   SET name = left(name, 200) || ' (retired ' || left(id::text, 8) || ')'
 WHERE retired_at IS NOT NULL;

ALTER TABLE scan_workflows
    ADD CONSTRAINT scan_workflows_name_version_unique UNIQUE (tenant_id, name, version);
DROP INDEX IF EXISTS uq_scan_workflows_live_name_version;

ALTER TABLE scan_runs DROP CONSTRAINT IF EXISTS scan_runs_scan_workflow_id_fkey;
ALTER TABLE scan_runs
    ADD CONSTRAINT scan_runs_scan_workflow_id_fkey
    FOREIGN KEY (scan_workflow_id) REFERENCES scan_workflows (id) ON DELETE CASCADE;

ALTER TABLE scan_workflows DROP COLUMN IF EXISTS retired_at;
