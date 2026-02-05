-- =============================================================================
-- Migration 016: Agents (Workers) and Commands
-- OpenCTEM OSS Edition
-- =============================================================================

-- Agents (formerly workers - scanners/collectors)
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'agent',
    description TEXT,
    capabilities TEXT[] DEFAULT '{}',
    tools TEXT[] DEFAULT '{}',
    execution_mode VARCHAR(20) DEFAULT 'standalone',
    status VARCHAR(50) DEFAULT 'pending',
    status_message VARCHAR(255),
    health VARCHAR(20) DEFAULT 'unknown',
    api_key_hash VARCHAR(64) NOT NULL,
    api_key_prefix VARCHAR(12) NOT NULL,
    version VARCHAR(50),
    hostname VARCHAR(255),
    ip_address INET,
    labels JSONB DEFAULT '{}',
    config JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    last_seen_at TIMESTAMPTZ,
    last_error_at TIMESTAMPTZ,
    last_offline_at TIMESTAMPTZ,
    total_findings BIGINT DEFAULT 0,
    total_scans BIGINT DEFAULT 0,
    error_count BIGINT DEFAULT 0,
    max_concurrent_jobs INTEGER DEFAULT 5,
    current_jobs INTEGER DEFAULT 0,

    -- Metrics for load balancing
    cpu_percent DECIMAL(5,2) DEFAULT 0,
    memory_percent DECIMAL(5,2) DEFAULT 0,
    disk_read_mbps NUMERIC(10,2),
    disk_write_mbps NUMERIC(10,2),
    network_rx_mbps NUMERIC(10,2),
    network_tx_mbps NUMERIC(10,2),
    load_score NUMERIC(10,4),
    metrics_updated_at TIMESTAMPTZ,
    last_error TEXT,
    region VARCHAR(64) DEFAULT '',

    -- Platform Agent (OSS: always FALSE - platform agents are Enterprise-only)
    is_platform_agent BOOLEAN NOT NULL DEFAULT FALSE,
    tier VARCHAR(20),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_agents_type CHECK (type IN ('worker', 'agent', 'scanner', 'collector', 'platform', 'runner', 'sensor')),
    CONSTRAINT chk_agents_tier CHECK (tier IS NULL OR tier IN ('shared', 'dedicated', 'premium')),
    CONSTRAINT chk_agents_execution_mode CHECK (execution_mode IN ('standalone', 'daemon')),
    CONSTRAINT chk_agents_status CHECK (status IN ('pending', 'active', 'inactive', 'error', 'revoked')),
    CONSTRAINT chk_agents_health CHECK (health IN ('healthy', 'degraded', 'unhealthy', 'unknown'))
);

COMMENT ON TABLE agents IS 'Security scanning agents (workers)';

-- Agent API Keys (Multiple keys per agent for rotation)
CREATE TABLE IF NOT EXISTS agent_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name VARCHAR(255) DEFAULT 'default',
    key_hash VARCHAR(64) NOT NULL,
    key_prefix VARCHAR(12) NOT NULL,
    scopes TEXT[] DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_ip INET,
    use_count BIGINT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE agent_api_keys IS 'API keys for agent authentication (supports rotation)';

-- Registration Tokens (Auto-registration)
CREATE TABLE IF NOT EXISTS registration_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL,
    token_prefix VARCHAR(12) NOT NULL,
    agent_type VARCHAR(50) DEFAULT 'agent',
    agent_name_prefix VARCHAR(100),
    default_scopes TEXT[] DEFAULT '{}',
    default_capabilities TEXT[] DEFAULT '{}',
    default_tools TEXT[] DEFAULT '{}',
    default_labels JSONB DEFAULT '{}',
    max_uses INTEGER DEFAULT 1,
    uses_count INTEGER DEFAULT 0,
    expires_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE registration_tokens IS 'Tokens for automatic agent registration';

-- Commands (Task queue for agents)
CREATE TABLE IF NOT EXISTS commands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    step_run_id UUID,
    type VARCHAR(50) NOT NULL,
    priority VARCHAR(20) DEFAULT 'normal',
    payload JSONB DEFAULT '{}',
    status VARCHAR(50) DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result JSONB,
    scheduled_at TIMESTAMPTZ,
    schedule_id UUID,

    -- Platform agent support
    is_platform_job BOOLEAN DEFAULT FALSE,
    platform_agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    auth_token_hash VARCHAR(64),
    auth_token_prefix VARCHAR(12),
    auth_token_expires_at TIMESTAMPTZ,
    queue_priority INTEGER DEFAULT 0,
    queued_at TIMESTAMPTZ,
    dispatch_attempts INTEGER DEFAULT 0,

    CONSTRAINT chk_command_type CHECK (type IN ('scan', 'collect', 'health_check', 'config_update', 'cancel', 'template_sync', 'update_tools', 'run_tool')),
    CONSTRAINT chk_command_priority CHECK (priority IN ('low', 'normal', 'high', 'critical')),
    CONSTRAINT chk_command_status CHECK (status IN ('pending', 'acknowledged', 'running', 'completed', 'failed', 'cancelled', 'expired'))
);

COMMENT ON TABLE commands IS 'Task queue for agent commands';
COMMENT ON COLUMN commands.is_platform_job IS 'Whether this is a platform-managed job';
COMMENT ON COLUMN commands.platform_agent_id IS 'Platform agent assigned to execute this job';
COMMENT ON COLUMN commands.queue_priority IS 'Calculated priority for queue ordering';
COMMENT ON COLUMN commands.queued_at IS 'When the job was added to the platform queue';
COMMENT ON COLUMN commands.dispatch_attempts IS 'Number of times this job was dispatched to an agent';

-- Agent Metrics (Performance tracking)
CREATE TABLE IF NOT EXISTS agent_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    metric_type VARCHAR(50) NOT NULL,
    metric_value DECIMAL(12,4) NOT NULL,
    labels JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE agent_metrics IS 'Agent performance metrics';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Agents indexes
CREATE INDEX IF NOT EXISTS idx_agents_tenant_id ON agents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agents_type ON agents(type);
CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_api_key_hash ON agents(api_key_hash);
CREATE INDEX IF NOT EXISTS idx_agents_api_key_prefix ON agents(api_key_prefix);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen_at ON agents(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_agents_last_offline_at ON agents(last_offline_at DESC) WHERE last_offline_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agents_execution_mode ON agents(execution_mode);
CREATE INDEX IF NOT EXISTS idx_agents_tools ON agents USING GIN(tools);
CREATE INDEX IF NOT EXISTS idx_agents_capabilities ON agents USING GIN(capabilities);
CREATE INDEX IF NOT EXISTS idx_agents_labels ON agents USING GIN(labels);
CREATE INDEX IF NOT EXISTS idx_agents_region ON agents(region) WHERE region != '';

-- Platform agent indexes
CREATE INDEX IF NOT EXISTS idx_agents_platform ON agents(is_platform_agent) WHERE is_platform_agent = TRUE;
CREATE INDEX IF NOT EXISTS idx_agents_tier ON agents(tier) WHERE tier IS NOT NULL;

-- Load balancing indexes
CREATE INDEX IF NOT EXISTS idx_agents_load_score ON agents(load_score ASC) WHERE status = 'active' AND health = 'healthy';
CREATE INDEX IF NOT EXISTS idx_agents_metrics_updated ON agents(metrics_updated_at DESC) WHERE metrics_updated_at IS NOT NULL;

-- Agent API keys indexes
CREATE INDEX IF NOT EXISTS idx_agent_api_keys_agent_id ON agent_api_keys(agent_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_api_keys_hash ON agent_api_keys(key_hash) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_agent_api_keys_prefix ON agent_api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_agent_api_keys_expires ON agent_api_keys(expires_at) WHERE expires_at IS NOT NULL;

-- Registration tokens indexes
CREATE INDEX IF NOT EXISTS idx_registration_tokens_tenant ON registration_tokens(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_registration_tokens_hash ON registration_tokens(token_hash) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_registration_tokens_prefix ON registration_tokens(token_prefix);
CREATE INDEX IF NOT EXISTS idx_registration_tokens_expires ON registration_tokens(expires_at) WHERE expires_at IS NOT NULL;

-- Commands indexes
CREATE INDEX IF NOT EXISTS idx_commands_tenant ON commands(tenant_id);
CREATE INDEX IF NOT EXISTS idx_commands_agent ON commands(agent_id);
CREATE INDEX IF NOT EXISTS idx_commands_type ON commands(type);
CREATE INDEX IF NOT EXISTS idx_commands_status ON commands(status);
CREATE INDEX IF NOT EXISTS idx_commands_priority ON commands(priority);
CREATE INDEX IF NOT EXISTS idx_commands_created ON commands(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_commands_expires ON commands(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_commands_scheduled ON commands(scheduled_at) WHERE scheduled_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_commands_schedule ON commands(schedule_id) WHERE schedule_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_commands_pending_poll ON commands(tenant_id, agent_id, status, priority, created_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_commands_pending_unassigned ON commands(tenant_id, status, type, priority, created_at) WHERE status = 'pending' AND agent_id IS NULL;

-- Platform job indexes
CREATE INDEX IF NOT EXISTS idx_commands_is_platform_job ON commands(is_platform_job) WHERE is_platform_job = TRUE;
CREATE INDEX IF NOT EXISTS idx_commands_platform_agent ON commands(platform_agent_id) WHERE platform_agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_commands_auth_token ON commands(auth_token_hash) WHERE auth_token_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_commands_queue_priority ON commands(queue_priority DESC, queued_at ASC) WHERE is_platform_job = TRUE AND status = 'pending';

-- Agent metrics indexes
CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_id ON agent_metrics(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_type ON agent_metrics(metric_type);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_recorded_at ON agent_metrics(recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_agent_type_time ON agent_metrics(agent_id, metric_type, recorded_at DESC);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_agents_updated_at ON agents;
CREATE TRIGGER trigger_agents_updated_at
    BEFORE UPDATE ON agents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Platform Job Queue Functions
-- =============================================================================

-- Calculate queue priority based on job priority, wait time, and tenant fairness
CREATE OR REPLACE FUNCTION calculate_queue_priority(
    p_priority VARCHAR,
    p_queued_at TIMESTAMPTZ,
    p_tenant_id UUID
) RETURNS INTEGER AS $$
DECLARE
    base_priority INTEGER;
    wait_time_minutes INTEGER;
    tenant_active_jobs INTEGER;
    final_priority INTEGER;
BEGIN
    -- Base priority from job priority level
    base_priority := CASE p_priority
        WHEN 'critical' THEN 1000
        WHEN 'high' THEN 750
        WHEN 'normal' THEN 500
        WHEN 'low' THEN 250
        ELSE 500
    END;

    -- Add wait time bonus (1 point per minute waiting, max 200)
    wait_time_minutes := EXTRACT(EPOCH FROM (NOW() - COALESCE(p_queued_at, NOW()))) / 60;
    wait_time_minutes := LEAST(wait_time_minutes, 200);

    -- Reduce priority if tenant has many active jobs (fairness)
    SELECT COUNT(*) INTO tenant_active_jobs
    FROM commands
    WHERE tenant_id = p_tenant_id
    AND is_platform_job = TRUE
    AND status IN ('acknowledged', 'running');

    final_priority := base_priority + wait_time_minutes - (tenant_active_jobs * 10);

    RETURN GREATEST(final_priority, 1);
END;
$$ LANGUAGE plpgsql;

-- Get next platform job for an agent (atomic claim with FOR UPDATE SKIP LOCKED)
CREATE OR REPLACE FUNCTION get_next_platform_job(
    p_agent_id UUID,
    p_capabilities TEXT[],
    p_tools TEXT[]
) RETURNS TABLE (
    command_id UUID,
    tenant_id UUID,
    command_type VARCHAR,
    payload JSONB,
    queued_at TIMESTAMPTZ,
    auth_token VARCHAR
) AS $$
DECLARE
    v_command_id UUID;
    v_tenant_id UUID;
    v_command_type VARCHAR;
    v_payload JSONB;
    v_queued_at TIMESTAMPTZ;
    v_auth_token_prefix VARCHAR;
BEGIN
    -- Find and claim the next available job
    SELECT c.id, c.tenant_id, c.type, c.payload, c.queued_at, c.auth_token_prefix
    INTO v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix
    FROM commands c
    WHERE c.is_platform_job = TRUE
    AND c.status = 'pending'
    AND c.platform_agent_id IS NULL
    AND (c.expires_at IS NULL OR c.expires_at > NOW())
    ORDER BY c.queue_priority DESC, c.queued_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

    IF v_command_id IS NULL THEN
        RETURN;
    END IF;

    -- Claim the job
    UPDATE commands
    SET platform_agent_id = p_agent_id,
        status = 'acknowledged',
        acknowledged_at = NOW(),
        dispatch_attempts = dispatch_attempts + 1
    WHERE id = v_command_id;

    RETURN QUERY SELECT v_command_id, v_tenant_id, v_command_type, v_payload, v_queued_at, v_auth_token_prefix;
END;
$$ LANGUAGE plpgsql;

-- Recover stuck platform jobs (jobs assigned but agent went offline)
CREATE OR REPLACE FUNCTION recover_stuck_platform_jobs(
    p_stuck_threshold_minutes INTEGER
) RETURNS INTEGER AS $$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_jobs AS (
        UPDATE commands
        SET platform_agent_id = NULL,
            status = 'pending',
            dispatch_attempts = dispatch_attempts
        WHERE is_platform_job = TRUE
        AND status = 'acknowledged'
        AND platform_agent_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        AND dispatch_attempts < 3
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_jobs;

    RETURN recovered_count;
END;
$$ LANGUAGE plpgsql;

-- Recover stuck tenant commands (commands assigned to offline agents)
CREATE OR REPLACE FUNCTION recover_stuck_tenant_commands(
    p_stuck_threshold_minutes INTEGER,
    p_max_retries INTEGER
) RETURNS INTEGER AS $$
DECLARE
    recovered_count INTEGER;
BEGIN
    WITH stuck_commands AS (
        UPDATE commands
        SET agent_id = NULL,
            status = 'pending'
        WHERE is_platform_job = FALSE
        AND status = 'acknowledged'
        AND agent_id IS NOT NULL
        AND acknowledged_at < NOW() - (p_stuck_threshold_minutes || ' minutes')::INTERVAL
        RETURNING id
    )
    SELECT COUNT(*) INTO recovered_count FROM stuck_commands;

    RETURN recovered_count;
END;
$$ LANGUAGE plpgsql;

-- Fail exhausted commands (exceeded max retries)
CREATE OR REPLACE FUNCTION fail_exhausted_commands(
    p_max_retries INTEGER
) RETURNS INTEGER AS $$
DECLARE
    failed_count INTEGER;
BEGIN
    WITH exhausted AS (
        UPDATE commands
        SET status = 'failed',
            error_message = 'Max dispatch attempts exceeded',
            completed_at = NOW()
        WHERE is_platform_job = TRUE
        AND status = 'pending'
        AND dispatch_attempts >= p_max_retries
        RETURNING id
    )
    SELECT COUNT(*) INTO failed_count FROM exhausted;

    RETURN failed_count;
END;
$$ LANGUAGE plpgsql;
