-- =============================================================================
-- Migration 040: Workflows (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_workflows_updated_at ON workflows;
DROP TABLE IF EXISTS workflow_node_runs;
DROP TABLE IF EXISTS workflow_runs;
DROP TABLE IF EXISTS workflow_edges;
DROP TABLE IF EXISTS workflow_nodes;
DROP TABLE IF EXISTS workflows;
