-- =============================================================================
-- Migration 033: Tool Executions
-- OpenCTEM OSS Edition
-- =============================================================================
-- Tool execution history for analytics and debugging.
-- Created separately from tools because it references agents table.

CREATE TABLE IF NOT EXISTS tool_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_id UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,

    -- Execution context
    pipeline_run_id UUID REFERENCES pipeline_runs(id) ON DELETE SET NULL,
    step_run_id UUID REFERENCES step_runs(id) ON DELETE SET NULL,

    -- Execution details
    status VARCHAR(20) NOT NULL DEFAULT 'running',

    -- Input/Output
    input_config JSONB DEFAULT '{}',
    targets_count INTEGER DEFAULT 0,

    -- Results
    findings_count INTEGER DEFAULT 0,
    output_summary JSONB DEFAULT '{}',
    error_message TEXT,

    -- Timing
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_tool_executions_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'timeout', 'cancelled'))
);

COMMENT ON TABLE tool_executions IS 'Tool execution history for analytics and debugging';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_tool_executions_tenant ON tool_executions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_tool ON tool_executions(tool_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_agent ON tool_executions(agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tool_executions_status ON tool_executions(status);
CREATE INDEX IF NOT EXISTS idx_tool_executions_started ON tool_executions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tool_executions_pipeline ON tool_executions(pipeline_run_id) WHERE pipeline_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tool_executions_step ON tool_executions(step_run_id) WHERE step_run_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tool_executions_tenant_tool ON tool_executions(tenant_id, tool_id);
CREATE INDEX IF NOT EXISTS idx_tool_executions_completed ON tool_executions(completed_at DESC) WHERE status = 'completed';
