-- Automations are named the same at every layer (glossary: an event rule
-- When/If/Then is an automation; "workflow" is a scan workflow). Renames, no
-- copies and no compatibility views: workflows -> automations,
-- workflow_nodes -> automation_nodes, workflow_edges -> automation_edges,
-- workflow_runs -> automation_runs, workflow_node_runs -> automation_run_steps,
-- the workflow_id / workflow_run_id columns, and every index, constraint,
-- trigger and RLS policy named after them. Data, ids and API routes do not
-- change.
--
-- expand-contract-ok: one-step rename; the api that reads the new names ships in the same release (stop the old api before migrating)
ALTER TABLE workflows RENAME TO automations;
ALTER TABLE workflow_nodes RENAME TO automation_nodes;
ALTER TABLE workflow_edges RENAME TO automation_edges;
ALTER TABLE workflow_runs RENAME TO automation_runs;
ALTER TABLE workflow_node_runs RENAME TO automation_run_steps;
ALTER TABLE automation_nodes RENAME COLUMN workflow_id TO automation_id;
ALTER TABLE automation_edges RENAME COLUMN workflow_id TO automation_id;
ALTER TABLE automation_runs RENAME COLUMN workflow_id TO automation_id;
ALTER TABLE automation_run_steps RENAME COLUMN workflow_run_id TO automation_run_id;
ALTER TABLE automation_edges RENAME CONSTRAINT chk_workflow_edge_no_self_loop TO chk_automation_edge_no_self_loop;
ALTER TABLE automation_edges RENAME CONSTRAINT workflow_edges_pkey TO automation_edges_pkey;
ALTER TABLE automation_edges RENAME CONSTRAINT workflow_edges_workflow_id_fkey TO automation_edges_automation_id_fkey;
ALTER TABLE automation_run_steps RENAME CONSTRAINT workflow_node_runs_node_id_fkey TO automation_run_steps_node_id_fkey;
ALTER TABLE automation_run_steps RENAME CONSTRAINT workflow_node_runs_pkey TO automation_run_steps_pkey;
ALTER TABLE automation_run_steps RENAME CONSTRAINT workflow_node_runs_workflow_run_id_fkey TO automation_run_steps_automation_run_id_fkey;
ALTER TABLE automation_nodes RENAME CONSTRAINT uq_workflow_node_key TO uq_automation_node_key;
ALTER TABLE automation_nodes RENAME CONSTRAINT workflow_nodes_pkey TO automation_nodes_pkey;
ALTER TABLE automation_nodes RENAME CONSTRAINT workflow_nodes_workflow_id_fkey TO automation_nodes_automation_id_fkey;
ALTER TABLE automation_runs RENAME CONSTRAINT workflow_runs_pkey TO automation_runs_pkey;
ALTER TABLE automation_runs RENAME CONSTRAINT workflow_runs_tenant_id_fkey TO automation_runs_tenant_id_fkey;
ALTER TABLE automation_runs RENAME CONSTRAINT workflow_runs_triggered_by_fkey TO automation_runs_triggered_by_fkey;
ALTER TABLE automation_runs RENAME CONSTRAINT workflow_runs_workflow_id_fkey TO automation_runs_automation_id_fkey;
ALTER TABLE automations RENAME CONSTRAINT uq_workflow_name TO uq_automation_name;
ALTER TABLE automations RENAME CONSTRAINT workflows_created_by_fkey TO automations_created_by_fkey;
ALTER TABLE automations RENAME CONSTRAINT workflows_pkey TO automations_pkey;
ALTER TABLE automations RENAME CONSTRAINT workflows_tenant_id_fkey TO automations_tenant_id_fkey;
ALTER INDEX idx_uq_workflow_edge RENAME TO idx_uq_automation_edge;
ALTER INDEX idx_uq_workflow_node_run RENAME TO idx_uq_automation_run_step;
ALTER INDEX idx_workflow_node_runs_node RENAME TO idx_automation_run_steps_node;
ALTER INDEX idx_workflow_node_runs_pending RENAME TO idx_automation_run_steps_pending;
ALTER INDEX idx_workflow_node_runs_status RENAME TO idx_automation_run_steps_status;
ALTER INDEX idx_workflow_nodes_type RENAME TO idx_automation_nodes_type;
ALTER INDEX idx_workflow_runs_active RENAME TO idx_automation_runs_active;
ALTER INDEX idx_workflow_runs_created RENAME TO idx_automation_runs_created;
ALTER INDEX idx_workflow_runs_status RENAME TO idx_automation_runs_status;
ALTER INDEX idx_workflow_runs_subject RENAME TO idx_automation_runs_subject;
ALTER INDEX idx_workflow_runs_tenant RENAME TO idx_automation_runs_tenant;
ALTER INDEX idx_workflow_runs_tenant_active RENAME TO idx_automation_runs_tenant_active;
ALTER INDEX idx_workflow_runs_tenant_created RENAME TO idx_automation_runs_tenant_created;
ALTER INDEX idx_workflow_runs_workflow RENAME TO idx_automation_runs_automation;
ALTER INDEX idx_workflow_runs_workflow_created RENAME TO idx_automation_runs_automation_created;
ALTER INDEX uq_workflow_runs_idempotency RENAME TO uq_automation_runs_idempotency;
ALTER INDEX idx_workflows_active RENAME TO idx_automations_active;
ALTER INDEX idx_workflows_tags RENAME TO idx_automations_tags;
ALTER POLICY workflow_runs_tenant_isolation ON automation_runs RENAME TO automation_runs_tenant_isolation;
ALTER POLICY workflows_tenant_isolation ON automations RENAME TO automations_tenant_isolation;
ALTER TRIGGER trigger_workflows_updated_at ON automations RENAME TO trigger_automations_updated_at;
