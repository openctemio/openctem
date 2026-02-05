-- =============================================================================
-- Migration 021: Audit Logs
-- OpenCTEM OSS Edition
-- =============================================================================

-- Audit Logs (General user action audit trail)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_email VARCHAR(255),
    actor_ip VARCHAR(45),
    actor_agent TEXT,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    resource_name VARCHAR(500),
    changes JSONB,
    result VARCHAR(20) NOT NULL DEFAULT 'success',
    severity VARCHAR(20) NOT NULL DEFAULT 'low',
    message TEXT,
    metadata JSONB DEFAULT '{}',
    request_id VARCHAR(100),
    session_id VARCHAR(100),
    logged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_audit_logs_result CHECK (result IN ('success', 'failure', 'denied')),
    CONSTRAINT chk_audit_logs_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

COMMENT ON TABLE audit_logs IS 'General audit log for user actions';

-- Email Logs (Email delivery tracking)
CREATE TABLE IF NOT EXISTS email_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    email_type VARCHAR(100) NOT NULL,
    recipient_email VARCHAR(255) NOT NULL,
    subject VARCHAR(500),
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    task_id VARCHAR(255),
    queue_name VARCHAR(100),
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    last_error TEXT,
    related_entity_type VARCHAR(100),
    related_entity_id UUID,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    queued_at TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,

    CONSTRAINT chk_email_logs_status CHECK (status IN ('pending', 'queued', 'processing', 'sent', 'failed', 'bounced'))
);

COMMENT ON TABLE email_logs IS 'Email delivery tracking';

-- Agent Audit Logs (Audit log for agent/worker activities)
CREATE TABLE IF NOT EXISTS agent_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    api_key_id UUID REFERENCES agent_api_keys(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL,
    event_action VARCHAR(100) NOT NULL,
    event_status VARCHAR(20) NOT NULL,
    ip_address INET,
    user_agent VARCHAR(500),
    request_id VARCHAR(100),
    details JSONB DEFAULT '{}',
    error_message TEXT,
    duration_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_agent_audit_logs_status CHECK (event_status IN ('success', 'failure', 'denied'))
);

COMMENT ON TABLE agent_audit_logs IS 'Audit log for agent activities';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_logged_at ON audit_logs(tenant_id, logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_logged_at ON audit_logs(actor_id, logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_logged_at ON audit_logs(action, logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_severity_logged_at ON audit_logs(severity, logged_at DESC) WHERE severity IN ('high', 'critical');
CREATE INDEX IF NOT EXISTS idx_audit_logs_logged_at ON audit_logs(logged_at DESC);

-- Email logs indexes
CREATE INDEX IF NOT EXISTS idx_email_logs_recipient ON email_logs(recipient_email);
CREATE INDEX IF NOT EXISTS idx_email_logs_status ON email_logs(status);
CREATE INDEX IF NOT EXISTS idx_email_logs_email_type ON email_logs(email_type);
CREATE INDEX IF NOT EXISTS idx_email_logs_tenant_id ON email_logs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_email_logs_created_at ON email_logs(created_at DESC);

-- Agent audit logs indexes
CREATE INDEX IF NOT EXISTS idx_agent_audit_logs_tenant ON agent_audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_audit_logs_agent ON agent_audit_logs(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_audit_logs_type ON agent_audit_logs(event_type, created_at DESC);

