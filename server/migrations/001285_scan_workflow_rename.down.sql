-- Reverses 001285: the old table, column, index, constraint, policy and
-- trigger names, the old payload keys, the scan_pipelines module and the
-- integrations:pipelines:{read,write,delete} permissions.

-- Permissions back to the old ids.
INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
SELECT v.old_id, 'integrations', v.name, v.description, p.is_active, p.created_at
FROM (VALUES
    ('scans:workflows:read',   'integrations:pipelines:read',   'View Pipelines',   'View pipeline configurations'),
    ('scans:workflows:write',  'integrations:pipelines:write',  'Manage Pipelines', 'Create and update pipelines'),
    ('scans:workflows:delete', 'integrations:pipelines:delete', 'Delete Pipelines', 'Remove pipelines')
) AS v(new_id, old_id, name, description)
JOIN permissions p ON p.id = v.new_id
ON CONFLICT (id) DO NOTHING;
UPDATE role_permissions SET permission_id = replace(permission_id, 'scans:workflows:', 'integrations:pipelines:')
WHERE permission_id IN ('scans:workflows:read', 'scans:workflows:write', 'scans:workflows:delete');
UPDATE granular_permission_backfill SET permission_id = replace(permission_id, 'scans:workflows:', 'integrations:pipelines:')
WHERE permission_id IN ('scans:workflows:read', 'scans:workflows:write', 'scans:workflows:delete');
UPDATE api_keys SET scopes = array_replace(array_replace(array_replace(scopes,
    'scans:workflows:read', 'integrations:pipelines:read'),
    'scans:workflows:write', 'integrations:pipelines:write'),
    'scans:workflows:delete', 'integrations:pipelines:delete')
WHERE scopes && ARRAY['scans:workflows:read', 'scans:workflows:write', 'scans:workflows:delete']::text[];
UPDATE licenses SET permissions = array_replace(array_replace(array_replace(permissions,
    'scans:workflows:read', 'integrations:pipelines:read'),
    'scans:workflows:write', 'integrations:pipelines:write'),
    'scans:workflows:delete', 'integrations:pipelines:delete')
WHERE permissions && ARRAY['scans:workflows:read', 'scans:workflows:write', 'scans:workflows:delete']::text[];
DELETE FROM permissions WHERE id IN ('scans:workflows:read', 'scans:workflows:write', 'scans:workflows:delete');

-- Modules.
INSERT INTO modules
SELECT r.* FROM access_control_removed_archive a, jsonb_populate_record(NULL::modules, a.row_data) r
WHERE a.source_table = 'modules:001285'
ON CONFLICT (id) DO NOTHING;
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, release_status, parent_module_id, created_at, updated_at, is_core)
SELECT 'scan_pipelines', 'scan-pipelines', 'Scan Pipelines',
       'Multi-step scan pipelines (scope → fingerprint → scan → triage)',
       icon, category, display_order, is_active, release_status, parent_module_id, created_at, now(), is_core
FROM modules WHERE id = 'scan_workflows'
ON CONFLICT (id) DO NOTHING;
UPDATE tenant_modules SET module_id = 'scan_pipelines' WHERE module_id = 'scan_workflows';
UPDATE permissions SET module_id = 'scan_pipelines' WHERE module_id = 'scan_workflows';
UPDATE event_types SET module_id = 'scan_pipelines' WHERE module_id = 'scan_workflows';
UPDATE asset_types SET module_id = 'scan_pipelines' WHERE module_id = 'scan_workflows';
UPDATE modules SET parent_module_id = 'scan_pipelines' WHERE parent_module_id = 'scan_workflows';
DELETE FROM modules WHERE id = 'scan_workflows';

DELETE FROM access_control_removed_archive
WHERE source_table = 'modules:001285';

-- Command payload keys.
DROP INDEX IF EXISTS idx_commands_scan_run;
UPDATE commands
SET payload = (payload - 'scan_run_id' - 'scan_run_step_id')
    || jsonb_strip_nulls(jsonb_build_object(
           'pipeline_run_id', payload->'scan_run_id',
           'step_run_id', payload->'scan_run_step_id'))
WHERE payload ? 'scan_run_id' OR payload ? 'scan_run_step_id';
CREATE INDEX idx_commands_pipeline_run ON commands (tenant_id, (payload->>'pipeline_run_id'))
    WHERE payload->>'pipeline_run_id' IS NOT NULL;

-- Indexes and constraints.
ALTER INDEX idx_commands_scan_run_step_id RENAME TO idx_commands_step_run_id;
ALTER INDEX idx_scan_run_steps_command RENAME TO idx_step_runs_command;
ALTER INDEX idx_scan_run_steps_order RENAME TO idx_step_runs_order;
ALTER INDEX idx_scan_run_steps_sensor RENAME TO idx_step_runs_sensor;
ALTER INDEX idx_scan_run_steps_status RENAME TO idx_step_runs_status;
ALTER INDEX idx_scan_run_steps_step RENAME TO idx_step_runs_step;
ALTER INDEX idx_scan_runs_asset RENAME TO idx_pipeline_runs_asset;
ALTER INDEX idx_scan_runs_created RENAME TO idx_pipeline_runs_created;
ALTER INDEX idx_scan_runs_open_deadline RENAME TO idx_pipeline_runs_open_deadline;
ALTER INDEX idx_scan_runs_pending_started RENAME TO idx_pipeline_runs_pending_started;
ALTER INDEX idx_scan_runs_retry_eligible RENAME TO idx_pipeline_runs_retry_eligible;
ALTER INDEX idx_scan_runs_scan RENAME TO idx_pipeline_runs_scan;
ALTER INDEX idx_scan_runs_scan_workflow RENAME TO idx_pipeline_runs_pipeline;
ALTER INDEX idx_scan_runs_tenant RENAME TO idx_pipeline_runs_tenant;
ALTER INDEX idx_scan_runs_tenant_status_created RENAME TO idx_pipeline_runs_tenant_status_created;
ALTER INDEX idx_scan_runs_trigger RENAME TO idx_pipeline_runs_trigger;
ALTER INDEX idx_scan_workflow_steps_capabilities RENAME TO idx_pipeline_steps_capabilities;
ALTER INDEX idx_scan_workflow_steps_order RENAME TO idx_pipeline_steps_order;
ALTER INDEX idx_scan_workflow_steps_tool_id RENAME TO idx_pipeline_steps_tool_id;
ALTER INDEX idx_scan_workflows_active RENAME TO idx_pipeline_templates_active;
ALTER INDEX idx_scan_workflows_system RENAME TO idx_pipeline_templates_system;
ALTER INDEX idx_scan_workflows_tags RENAME TO idx_pipeline_templates_tags;
ALTER INDEX idx_scans_scan_workflow RENAME TO idx_scans_pipeline;
ALTER INDEX idx_tool_executions_scan_run RENAME TO idx_tool_executions_pipeline;
ALTER INDEX uq_scan_runs_scan_occurrence RENAME TO uq_pipeline_runs_scan_occurrence;
ALTER INDEX uq_scan_runs_tenant_id_id RENAME TO uq_pipeline_runs_tenant_id_id;
ALTER TABLE commands RENAME CONSTRAINT commands_scan_run_step_id_fkey TO commands_step_run_id_fkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT chk_scan_run_steps_status TO chk_step_runs_status;
ALTER TABLE scan_run_steps RENAME CONSTRAINT scan_run_steps_command_id_fkey TO step_runs_command_id_fkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT scan_run_steps_pkey TO step_runs_pkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT scan_run_steps_scan_run_id_fkey TO step_runs_pipeline_run_id_fkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT scan_run_steps_sensor_id_fkey TO step_runs_sensor_id_fkey;
ALTER TABLE scan_run_steps RENAME CONSTRAINT scan_run_steps_step_id_fkey TO step_runs_step_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT chk_scan_runs_status TO chk_pipeline_runs_status;
ALTER TABLE scan_runs RENAME CONSTRAINT chk_scan_runs_trigger_type TO chk_pipeline_runs_trigger_type;
ALTER TABLE scan_runs RENAME CONSTRAINT chk_scan_runs_unfinished_targets TO chk_pipeline_runs_unfinished_targets;
ALTER TABLE scan_runs RENAME CONSTRAINT fk_scan_runs_scan TO fk_pipeline_runs_scan;
ALTER TABLE scan_runs RENAME CONSTRAINT fk_scan_runs_tenant_asset TO fk_pipeline_runs_tenant_asset;
ALTER TABLE scan_runs RENAME CONSTRAINT scan_runs_asset_id_fkey TO pipeline_runs_asset_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT scan_runs_pkey TO pipeline_runs_pkey;
ALTER TABLE scan_runs RENAME CONSTRAINT scan_runs_scan_profile_id_fkey TO pipeline_runs_scan_profile_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT scan_runs_scan_workflow_id_fkey TO pipeline_runs_pipeline_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT scan_runs_sensor_id_fkey TO pipeline_runs_sensor_id_fkey;
ALTER TABLE scan_runs RENAME CONSTRAINT scan_runs_tenant_id_fkey TO pipeline_runs_tenant_id_fkey;
ALTER TABLE scan_step_outputs RENAME CONSTRAINT scan_step_outputs_scan_run_step_id_fkey TO scan_step_outputs_step_run_id_fkey;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT chk_scan_workflow_steps_condition_type TO chk_pipeline_steps_condition_type;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT scan_workflow_steps_key_unique TO pipeline_steps_key_unique;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT scan_workflow_steps_pkey TO pipeline_steps_pkey;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT scan_workflow_steps_scan_workflow_id_fkey TO pipeline_steps_pipeline_id_fkey;
ALTER TABLE scan_workflow_steps RENAME CONSTRAINT scan_workflow_steps_tool_id_fkey TO pipeline_steps_tool_id_fkey;
ALTER TABLE scan_workflows RENAME CONSTRAINT scan_workflows_created_by_fkey TO pipeline_templates_created_by_fkey;
ALTER TABLE scan_workflows RENAME CONSTRAINT scan_workflows_name_version_unique TO pipeline_templates_name_version_unique;
ALTER TABLE scan_workflows RENAME CONSTRAINT scan_workflows_pkey TO pipeline_templates_pkey;
ALTER TABLE scan_workflows RENAME CONSTRAINT scan_workflows_tenant_id_fkey TO pipeline_templates_tenant_id_fkey;
ALTER TABLE scans RENAME CONSTRAINT scans_chk_workflow_has_scan_workflow TO scans_chk_workflow_has_pipeline;
ALTER TABLE scans RENAME CONSTRAINT scans_scan_workflow_id_fkey TO scans_pipeline_id_fkey;
ALTER TABLE tool_executions RENAME CONSTRAINT tool_executions_scan_run_id_fkey TO tool_executions_pipeline_run_id_fkey;
ALTER TABLE tool_executions RENAME CONSTRAINT tool_executions_scan_run_step_id_fkey TO tool_executions_step_run_id_fkey;

ALTER TRIGGER trigger_scan_workflows_updated_at ON scan_workflows RENAME TO trigger_pipeline_templates_updated_at;
ALTER POLICY scan_workflows_tenant_isolation ON scan_workflows RENAME TO pipeline_templates_tenant_isolation;
ALTER POLICY scan_runs_tenant_isolation ON scan_runs RENAME TO pipeline_runs_tenant_isolation;

ALTER TABLE tool_executions RENAME COLUMN scan_run_step_id TO step_run_id;
ALTER TABLE tool_executions RENAME COLUMN scan_run_id TO pipeline_run_id;
ALTER TABLE scan_step_outputs RENAME COLUMN scan_run_step_id TO step_run_id;
ALTER TABLE commands RENAME COLUMN scan_run_step_id TO step_run_id;
ALTER TABLE scan_run_steps RENAME COLUMN scan_run_id TO pipeline_run_id;
ALTER TABLE scan_workflow_steps RENAME COLUMN scan_workflow_id TO pipeline_id;
ALTER TABLE scan_runs RENAME COLUMN scan_workflow_id TO pipeline_id;
ALTER TABLE scans RENAME COLUMN scan_workflow_id TO pipeline_id;

ALTER TABLE scan_run_steps RENAME TO step_runs;
ALTER TABLE scan_runs RENAME TO pipeline_runs;
ALTER TABLE scan_workflow_steps RENAME TO pipeline_steps;
ALTER TABLE scan_workflows RENAME TO pipeline_templates;
