-- expand-contract-ok: one-step rename (owner rule: minimal back-compat, no aliases); the API that reads the new names ships in the same release and the deploy runs migrations before the API starts (changelog upgrade note).
-- Scan workflow naming at every layer (glossary: "pipeline" is a CI word).
--
--   pipeline_templates -> scan_workflows       (the graph of steps a Scan runs)
--   pipeline_steps     -> scan_workflow_steps
--   pipeline_runs      -> scan_runs            (one execution of a Scan)
--   step_runs          -> scan_run_steps       (one step of a scan run)
--
-- Every object is renamed in place (ALTER ... RENAME): no row is copied, ids
-- and foreign keys stay, and the renames take a brief ACCESS EXCLUSIVE lock
-- on each table only for the catalog change. Indexes, constraints, the RLS
-- policies and the updated_at trigger follow the new names.
--
-- Columns that name the old tables follow too: pipeline_id ->
-- scan_workflow_id, pipeline_run_id -> scan_run_id, step_run_id ->
-- scan_run_step_id (scans, scan_runs, scan_workflow_steps, scan_run_steps,
-- commands, scan_step_outputs, tool_executions). ci_runs.pipeline_id is a CI
-- pipeline and keeps its name.
--
-- Command payloads carry the run they belong to under the same key: every
-- stored payload is rewritten (pipeline_run_id -> scan_run_id, step_run_id
-- -> scan_run_step_id), so commands queued before the upgrade still report
-- back to their run. Sensors do not read these keys.
--
-- Permissions: integrations:pipelines:{read,write,delete} become
-- scans:workflows:{read,write,delete}, one to one, in role grants, the
-- granular backfill ledger, API key scopes and licenses: nobody gains or
-- loses access. integrations:pipelines:execute is removed by 001241. The
-- module scan_pipelines
-- becomes scan_workflows; the deprecated "pipelines" module row (no tenant
-- enables it, nothing references it) is deleted.
--
-- Audit rows are not rewritten: the audit chain hashes them. Old entries keep
-- pipeline_template.* / pipeline_run.* actions; new ones use scan_workflow.*
-- and scan_run.*.

ALTER TABLE pipeline_templates RENAME TO scan_workflows;
ALTER TABLE pipeline_steps RENAME TO scan_workflow_steps;
ALTER TABLE pipeline_runs RENAME TO scan_runs;
ALTER TABLE step_runs RENAME TO scan_run_steps;

ALTER TABLE scans RENAME COLUMN pipeline_id TO scan_workflow_id;
ALTER TABLE scan_runs RENAME COLUMN pipeline_id TO scan_workflow_id;
ALTER TABLE scan_workflow_steps RENAME COLUMN pipeline_id TO scan_workflow_id;
ALTER TABLE scan_run_steps RENAME COLUMN pipeline_run_id TO scan_run_id;
ALTER TABLE commands RENAME COLUMN step_run_id TO scan_run_step_id;
ALTER TABLE scan_step_outputs RENAME COLUMN step_run_id TO scan_run_step_id;
ALTER TABLE tool_executions RENAME COLUMN pipeline_run_id TO scan_run_id;
ALTER TABLE tool_executions RENAME COLUMN step_run_id TO scan_run_step_id;

ALTER POLICY pipeline_runs_tenant_isolation ON scan_runs RENAME TO scan_runs_tenant_isolation;
ALTER POLICY pipeline_templates_tenant_isolation ON scan_workflows RENAME TO scan_workflows_tenant_isolation;
ALTER TRIGGER trigger_pipeline_templates_updated_at ON scan_workflows RENAME TO trigger_scan_workflows_updated_at;

-- Indexes and constraints that name the old tables or columns.
ALTER INDEX idx_commands_step_run_id RENAME TO idx_commands_scan_run_step_id;
ALTER INDEX idx_pipeline_runs_asset RENAME TO idx_scan_runs_asset;
ALTER INDEX idx_pipeline_runs_created RENAME TO idx_scan_runs_created;
ALTER INDEX idx_pipeline_runs_open_deadline RENAME TO idx_scan_runs_open_deadline;
ALTER INDEX idx_pipeline_runs_pending_started RENAME TO idx_scan_runs_pending_started;
ALTER INDEX idx_pipeline_runs_pipeline RENAME TO idx_scan_runs_scan_workflow;
ALTER INDEX idx_pipeline_runs_retry_eligible RENAME TO idx_scan_runs_retry_eligible;
ALTER INDEX idx_pipeline_runs_scan RENAME TO idx_scan_runs_scan;
ALTER INDEX idx_pipeline_runs_tenant RENAME TO idx_scan_runs_tenant;
ALTER INDEX idx_pipeline_runs_tenant_status_created RENAME TO idx_scan_runs_tenant_status_created;
ALTER INDEX idx_pipeline_runs_trigger RENAME TO idx_scan_runs_trigger;
ALTER INDEX idx_pipeline_steps_capabilities RENAME TO idx_scan_workflow_steps_capabilities;
ALTER INDEX idx_pipeline_steps_order RENAME TO idx_scan_workflow_steps_order;
ALTER INDEX idx_pipeline_steps_tool_id RENAME TO idx_scan_workflow_steps_tool_id;
ALTER INDEX idx_pipeline_templates_active RENAME TO idx_scan_workflows_active;
ALTER INDEX idx_pipeline_templates_system RENAME TO idx_scan_workflows_system;
ALTER INDEX idx_pipeline_templates_tags RENAME TO idx_scan_workflows_tags;
ALTER INDEX idx_scans_pipeline RENAME TO idx_scans_scan_workflow;
ALTER INDEX idx_step_runs_command RENAME TO idx_scan_run_steps_command;
ALTER INDEX idx_step_runs_order RENAME TO idx_scan_run_steps_order;
ALTER INDEX idx_step_runs_sensor RENAME TO idx_scan_run_steps_sensor;
ALTER INDEX idx_step_runs_status RENAME TO idx_scan_run_steps_status;
ALTER INDEX idx_step_runs_step RENAME TO idx_scan_run_steps_step;
ALTER INDEX idx_tool_executions_pipeline RENAME TO idx_tool_executions_scan_run;
ALTER INDEX uq_pipeline_runs_scan_occurrence RENAME TO uq_scan_runs_scan_occurrence;
ALTER INDEX uq_pipeline_runs_tenant_id_id RENAME TO uq_scan_runs_tenant_id_id;
ALTER TABLE commands RENAME CONSTRAINT commands_step_run_id_fkey TO commands_scan_run_step_id_fkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT chk_step_runs_status TO chk_scan_run_steps_status;
ALTER TABLE scan_run_steps RENAME CONSTRAINT step_runs_command_id_fkey TO scan_run_steps_command_id_fkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT step_runs_pipeline_run_id_fkey TO scan_run_steps_scan_run_id_fkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT step_runs_pkey TO scan_run_steps_pkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT step_runs_sensor_id_fkey TO scan_run_steps_sensor_id_fkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT step_runs_step_id_fkey TO scan_run_steps_step_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT chk_pipeline_runs_status TO chk_scan_runs_status;
ALTER TABLE scan_runs RENAME CONSTRAINT chk_pipeline_runs_trigger_type TO chk_scan_runs_trigger_type;
ALTER TABLE scan_runs RENAME CONSTRAINT chk_pipeline_runs_unfinished_targets TO chk_scan_runs_unfinished_targets;
ALTER TABLE scan_runs RENAME CONSTRAINT fk_pipeline_runs_scan TO fk_scan_runs_scan;
ALTER TABLE scan_runs RENAME CONSTRAINT fk_pipeline_runs_tenant_asset TO fk_scan_runs_tenant_asset;
ALTER TABLE scan_runs RENAME CONSTRAINT pipeline_runs_asset_id_fkey TO scan_runs_asset_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT pipeline_runs_pipeline_id_fkey TO scan_runs_scan_workflow_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT pipeline_runs_pkey TO scan_runs_pkey;
ALTER TABLE scan_runs RENAME CONSTRAINT pipeline_runs_scan_profile_id_fkey TO scan_runs_scan_profile_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT pipeline_runs_sensor_id_fkey TO scan_runs_sensor_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT pipeline_runs_tenant_id_fkey TO scan_runs_tenant_id_fkey;
ALTER TABLE scan_step_outputs RENAME CONSTRAINT scan_step_outputs_step_run_id_fkey TO scan_step_outputs_scan_run_step_id_fkey;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT chk_pipeline_steps_condition_type TO chk_scan_workflow_steps_condition_type;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT pipeline_steps_key_unique TO scan_workflow_steps_key_unique;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT pipeline_steps_pipeline_id_fkey TO scan_workflow_steps_scan_workflow_id_fkey;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT pipeline_steps_pkey TO scan_workflow_steps_pkey;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT pipeline_steps_tool_id_fkey TO scan_workflow_steps_tool_id_fkey;
ALTER TABLE scan_workflows RENAME CONSTRAINT pipeline_templates_created_by_fkey TO scan_workflows_created_by_fkey;
ALTER TABLE scan_workflows RENAME CONSTRAINT pipeline_templates_name_version_unique TO scan_workflows_name_version_unique;
ALTER TABLE scan_workflows RENAME CONSTRAINT pipeline_templates_pkey TO scan_workflows_pkey;
ALTER TABLE scan_workflows RENAME CONSTRAINT pipeline_templates_tenant_id_fkey TO scan_workflows_tenant_id_fkey;
ALTER TABLE scans RENAME CONSTRAINT scans_chk_workflow_has_pipeline TO scans_chk_workflow_has_scan_workflow;
ALTER TABLE scans RENAME CONSTRAINT scans_pipeline_id_fkey TO scans_scan_workflow_id_fkey;
ALTER TABLE tool_executions RENAME CONSTRAINT tool_executions_pipeline_run_id_fkey TO tool_executions_scan_run_id_fkey;
ALTER TABLE tool_executions RENAME CONSTRAINT tool_executions_step_run_id_fkey TO tool_executions_scan_run_step_id_fkey;

-- Command payload keys. The expression index on the old key is rebuilt on
-- the new one (commands is small: it is purged as commands finish).
DROP INDEX IF EXISTS idx_commands_pipeline_run;
UPDATE commands
SET payload = (payload - 'pipeline_run_id' - 'step_run_id')
    || jsonb_strip_nulls(jsonb_build_object(
           'scan_run_id', payload->'pipeline_run_id',
           'scan_run_step_id', payload->'step_run_id'))
WHERE payload ? 'pipeline_run_id' OR payload ? 'step_run_id';
CREATE INDEX idx_commands_scan_run ON commands (tenant_id, (payload->>'scan_run_id'))
    WHERE payload->>'scan_run_id' IS NOT NULL;

-- Module: scan_pipelines -> scan_workflows. tenant_modules has no ON UPDATE
-- CASCADE, so the new row is added, references move, and the old row goes.
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, release_status, parent_module_id, created_at, updated_at, is_core)
SELECT 'scan_workflows', 'scan-workflows', 'Scan Workflows',
       'Scan workflows: the steps a scan runs, chained by what each step finds',
       icon, category, display_order, is_active, release_status, parent_module_id, created_at, now(), is_core
FROM modules WHERE id = 'scan_pipelines'
ON CONFLICT (id) DO NOTHING;
UPDATE tenant_modules SET module_id = 'scan_workflows' WHERE module_id = 'scan_pipelines';
UPDATE permissions SET module_id = 'scan_workflows' WHERE module_id = 'scan_pipelines';
UPDATE event_types SET module_id = 'scan_workflows' WHERE module_id = 'scan_pipelines';
UPDATE asset_types SET module_id = 'scan_workflows' WHERE module_id = 'scan_pipelines';
UPDATE modules SET parent_module_id = 'scan_workflows' WHERE parent_module_id = 'scan_pipelines';
DELETE FROM modules WHERE id = 'scan_pipelines';

-- The deprecated "pipelines" module: archived, then deleted.
INSERT INTO access_control_removed_archive (source_table, row_data)
SELECT 'modules:001240', to_jsonb(m) FROM modules m WHERE m.id = 'pipelines';
DELETE FROM tenant_modules WHERE module_id = 'pipelines';
DELETE FROM modules WHERE id = 'pipelines';

-- Permissions: one old id maps to exactly one new id.
CREATE TEMP TABLE IF NOT EXISTS permission_renames_001240 (old_id VARCHAR(100) PRIMARY KEY, new_id VARCHAR(100) NOT NULL, name VARCHAR(100) NOT NULL, description TEXT NOT NULL);
INSERT INTO permission_renames_001240 (old_id, new_id, name, description) VALUES
    ('integrations:pipelines:read',   'scans:workflows:read',   'View scan workflows',   'View scan workflows and their steps'),
    ('integrations:pipelines:write',  'scans:workflows:write',  'Manage scan workflows', 'Create, edit and clone scan workflows'),
    ('integrations:pipelines:delete', 'scans:workflows:delete', 'Delete scan workflows', 'Delete scan workflows and their steps')
ON CONFLICT DO NOTHING;

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
SELECT r.new_id, 'scan_workflows', r.name, r.description, p.is_active, p.created_at
FROM permission_renames_001240 r JOIN permissions p ON p.id = r.old_id
ON CONFLICT (id) DO NOTHING;

UPDATE role_permissions rp SET permission_id = r.new_id
FROM permission_renames_001240 r WHERE rp.permission_id = r.old_id;
UPDATE granular_permission_backfill g SET permission_id = r.new_id
FROM permission_renames_001240 r WHERE g.permission_id = r.old_id;
UPDATE api_keys k SET scopes = array_replace(k.scopes, r.old_id, r.new_id)
FROM permission_renames_001240 r WHERE r.old_id = ANY(k.scopes);
UPDATE licenses l SET permissions = array_replace(l.permissions, r.old_id, r.new_id)
FROM permission_renames_001240 r WHERE r.old_id = ANY(l.permissions);
DELETE FROM permissions WHERE id IN (SELECT old_id FROM permission_renames_001240);
