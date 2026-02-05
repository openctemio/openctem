-- =============================================================================
-- Migration 018: Pipelines (Scan Orchestration)
-- OpenCTEM OSS Edition
-- =============================================================================

-- Pipeline Templates
CREATE TABLE IF NOT EXISTS pipeline_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    version INTEGER DEFAULT 1,
    triggers JSONB DEFAULT '[]',
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    is_system_template BOOLEAN DEFAULT FALSE,
    ui_positions JSONB DEFAULT '{}',
    ui_start_position JSONB,
    ui_end_position JSONB,
    tags TEXT[] DEFAULT '{}',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT pipeline_templates_name_version_unique UNIQUE (tenant_id, name, version)
);

COMMENT ON TABLE pipeline_templates IS 'Pipeline configuration templates';

-- Pipeline Steps
CREATE TABLE IF NOT EXISTS pipeline_steps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_id UUID NOT NULL REFERENCES pipeline_templates(id) ON DELETE CASCADE,
    step_key VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    step_order INTEGER NOT NULL,
    tool VARCHAR(100),
    capabilities TEXT[] DEFAULT '{}',
    config JSONB DEFAULT '{}',
    timeout_seconds INTEGER DEFAULT 1800,
    depends_on TEXT[] DEFAULT '{}',
    condition_type VARCHAR(50),
    condition_value TEXT,
    max_retries INTEGER DEFAULT 0,
    retry_delay_seconds INTEGER DEFAULT 60,
    ui_position_x INTEGER,
    ui_position_y INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_pipeline_steps_condition_type CHECK (condition_type IS NULL OR condition_type IN ('always', 'never', 'expression', 'asset_type', 'step_result')),
    CONSTRAINT pipeline_steps_key_unique UNIQUE (pipeline_id, step_key)
);

COMMENT ON TABLE pipeline_steps IS 'Individual steps within a pipeline';

-- Pipeline Runs
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_id UUID NOT NULL REFERENCES pipeline_templates(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scan_id UUID,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    trigger_type VARCHAR(50) NOT NULL,
    triggered_by VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    context JSONB DEFAULT '{}',
    total_steps INTEGER DEFAULT 0,
    completed_steps INTEGER DEFAULT 0,
    failed_steps INTEGER DEFAULT 0,
    skipped_steps INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    filtering_result JSONB,
    quality_gate_result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_pipeline_runs_trigger_type CHECK (trigger_type IN ('manual', 'schedule', 'webhook', 'api', 'on_asset_discovery')),
    CONSTRAINT chk_pipeline_runs_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'timeout'))
);

COMMENT ON TABLE pipeline_runs IS 'Pipeline execution instances';

-- Step Runs
CREATE TABLE IF NOT EXISTS step_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pipeline_run_id UUID NOT NULL REFERENCES pipeline_runs(id) ON DELETE CASCADE,
    step_id UUID NOT NULL REFERENCES pipeline_steps(id) ON DELETE CASCADE,
    step_key VARCHAR(100) NOT NULL,
    step_order INTEGER NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    command_id UUID REFERENCES commands(id) ON DELETE SET NULL,
    condition_evaluated BOOLEAN DEFAULT FALSE,
    condition_result BOOLEAN,
    skip_reason TEXT,
    findings_count INTEGER DEFAULT 0,
    output JSONB DEFAULT '{}',
    attempt INTEGER DEFAULT 1,
    max_attempts INTEGER DEFAULT 1,
    queued_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    error_code VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_step_runs_status CHECK (status IN ('pending', 'queued', 'running', 'completed', 'failed', 'skipped', 'cancelled', 'timeout'))
);

COMMENT ON TABLE step_runs IS 'Individual step execution records';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Pipeline templates indexes
CREATE INDEX IF NOT EXISTS idx_pipeline_templates_tenant ON pipeline_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_templates_active ON pipeline_templates(tenant_id, is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_pipeline_templates_system ON pipeline_templates(is_system_template) WHERE is_system_template = TRUE;
CREATE INDEX IF NOT EXISTS idx_pipeline_templates_tags ON pipeline_templates USING GIN(tags);

-- Pipeline steps indexes
CREATE INDEX IF NOT EXISTS idx_pipeline_steps_pipeline ON pipeline_steps(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_steps_order ON pipeline_steps(pipeline_id, step_order);
CREATE INDEX IF NOT EXISTS idx_pipeline_steps_capabilities ON pipeline_steps USING GIN(capabilities);

-- Pipeline runs indexes
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_pipeline ON pipeline_runs(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_tenant ON pipeline_runs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_asset ON pipeline_runs(asset_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_status ON pipeline_runs(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_trigger ON pipeline_runs(trigger_type);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_created ON pipeline_runs(created_at DESC);

-- Step runs indexes
CREATE INDEX IF NOT EXISTS idx_step_runs_pipeline_run ON step_runs(pipeline_run_id);
CREATE INDEX IF NOT EXISTS idx_step_runs_step ON step_runs(step_id);
CREATE INDEX IF NOT EXISTS idx_step_runs_status ON step_runs(pipeline_run_id, status);
CREATE INDEX IF NOT EXISTS idx_step_runs_agent ON step_runs(agent_id);
CREATE INDEX IF NOT EXISTS idx_step_runs_command ON step_runs(command_id);
CREATE INDEX IF NOT EXISTS idx_step_runs_order ON step_runs(pipeline_run_id, step_order);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_pipeline_templates_updated_at ON pipeline_templates;
CREATE TRIGGER trigger_pipeline_templates_updated_at
    BEFORE UPDATE ON pipeline_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Foreign Key: commands.step_run_id -> step_runs.id
-- (Added here since step_runs is created in this migration)
-- =============================================================================

DO $$ BEGIN
    ALTER TABLE commands
        ADD CONSTRAINT commands_step_run_id_fkey
        FOREIGN KEY (step_run_id) REFERENCES step_runs(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
