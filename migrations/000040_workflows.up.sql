-- =============================================================================
-- Migration 040: Workflows
-- OpenCTEM OSS Edition
-- =============================================================================
-- Automation workflows with trigger→condition→action→notification graph.
-- Supports visual editor with UI positioning and JSONB-based node configs.
-- =============================================================================

-- =============================================================================
-- Workflows
-- =============================================================================

CREATE TABLE IF NOT EXISTS workflows (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    tags TEXT[] DEFAULT '{}',

    -- Run Statistics
    total_runs INTEGER NOT NULL DEFAULT 0,
    successful_runs INTEGER NOT NULL DEFAULT 0,
    failed_runs INTEGER NOT NULL DEFAULT 0,
    last_run_id UUID,
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(20),

    -- Audit
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_workflow_name UNIQUE (tenant_id, name)
);

COMMENT ON TABLE workflows IS 'Automation workflows with visual graph editor';

-- =============================================================================
-- Workflow Nodes
-- =============================================================================

CREATE TABLE IF NOT EXISTS workflow_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    node_key VARCHAR(100) NOT NULL,
    node_type VARCHAR(20) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Visual Editor Position
    ui_position_x DOUBLE PRECISION NOT NULL DEFAULT 0,
    ui_position_y DOUBLE PRECISION NOT NULL DEFAULT 0,

    -- Node Configuration (type-specific)
    config JSONB NOT NULL DEFAULT '{}',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_node_type CHECK (node_type IN ('trigger', 'condition', 'action', 'notification')),
    CONSTRAINT uq_workflow_node_key UNIQUE (workflow_id, node_key)
);

COMMENT ON TABLE workflow_nodes IS 'Nodes in workflow graph (trigger, condition, action, notification)';
COMMENT ON COLUMN workflow_nodes.config IS 'Type-specific config: trigger_type, condition_expr, action_type/config, notification_type/config';

-- =============================================================================
-- Workflow Edges
-- =============================================================================

CREATE TABLE IF NOT EXISTS workflow_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    source_node_key VARCHAR(100) NOT NULL,
    target_node_key VARCHAR(100) NOT NULL,
    source_handle VARCHAR(20),
    label VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE workflow_edges IS 'Directed edges connecting workflow nodes';
COMMENT ON COLUMN workflow_edges.source_handle IS 'For condition nodes: yes/no branch handle';

-- =============================================================================
-- Workflow Runs
-- =============================================================================

CREATE TABLE IF NOT EXISTS workflow_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    trigger_type VARCHAR(50) NOT NULL,
    trigger_data JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    context JSONB DEFAULT '{}',

    -- Progress
    total_nodes INTEGER NOT NULL DEFAULT 0,
    completed_nodes INTEGER NOT NULL DEFAULT 0,
    failed_nodes INTEGER NOT NULL DEFAULT 0,

    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    -- Audit
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_run_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
);

COMMENT ON TABLE workflow_runs IS 'Execution instances of workflows';

-- =============================================================================
-- Workflow Node Runs
-- =============================================================================

CREATE TABLE IF NOT EXISTS workflow_node_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(id) ON DELETE CASCADE,
    node_id UUID NOT NULL REFERENCES workflow_nodes(id) ON DELETE CASCADE,
    node_key VARCHAR(100) NOT NULL,
    node_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    error_message TEXT,
    error_code VARCHAR(100),

    -- I/O
    input JSONB DEFAULT '{}',
    output JSONB DEFAULT '{}',
    condition_result BOOLEAN,

    -- Timing
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_node_run_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    CONSTRAINT chk_node_run_type CHECK (node_type IN ('trigger', 'condition', 'action', 'notification'))
);

COMMENT ON TABLE workflow_node_runs IS 'Execution state for each node within a workflow run';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Workflows
CREATE INDEX IF NOT EXISTS idx_workflows_tenant ON workflows(tenant_id);
CREATE INDEX IF NOT EXISTS idx_workflows_active ON workflows(tenant_id, is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_workflows_tags ON workflows USING GIN(tags);

-- Workflow Nodes
CREATE INDEX IF NOT EXISTS idx_workflow_nodes_workflow ON workflow_nodes(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_nodes_type ON workflow_nodes(node_type);

-- Workflow Edges
CREATE INDEX IF NOT EXISTS idx_workflow_edges_workflow ON workflow_edges(workflow_id);

-- Workflow Runs
CREATE INDEX IF NOT EXISTS idx_workflow_runs_workflow ON workflow_runs(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_tenant ON workflow_runs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_status ON workflow_runs(status);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_active ON workflow_runs(workflow_id, status)
    WHERE status IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS idx_workflow_runs_tenant_active ON workflow_runs(tenant_id, status)
    WHERE status IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS idx_workflow_runs_created ON workflow_runs(created_at DESC);

-- Workflow Node Runs
CREATE INDEX IF NOT EXISTS idx_workflow_node_runs_run ON workflow_node_runs(workflow_run_id);
CREATE INDEX IF NOT EXISTS idx_workflow_node_runs_node ON workflow_node_runs(node_id);
CREATE INDEX IF NOT EXISTS idx_workflow_node_runs_status ON workflow_node_runs(status);
CREATE INDEX IF NOT EXISTS idx_workflow_node_runs_pending ON workflow_node_runs(workflow_run_id, status)
    WHERE status = 'pending';

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_workflows_updated_at ON workflows;
CREATE TRIGGER trigger_workflows_updated_at
    BEFORE UPDATE ON workflows
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
