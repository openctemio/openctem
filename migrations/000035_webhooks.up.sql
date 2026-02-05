-- =============================================================================
-- Migration 000035: Webhooks
-- OpenCTEM OSS Edition
-- =============================================================================
-- Outgoing webhook configuration for event notifications.
-- =============================================================================

CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenant Isolation
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Endpoint
    url VARCHAR(1000) NOT NULL,
    secret_encrypted BYTEA,                         -- HMAC signing secret

    -- Events
    event_types TEXT[] NOT NULL DEFAULT '{}',       -- Events to send

    -- Filters
    severity_threshold VARCHAR(20) DEFAULT 'medium',
    asset_group_ids UUID[] DEFAULT '{}',
    tags TEXT[] DEFAULT '{}',

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active',

    -- Retry Configuration
    max_retries INTEGER NOT NULL DEFAULT 3,
    retry_interval_seconds INTEGER NOT NULL DEFAULT 60,

    -- Statistics
    total_sent INTEGER NOT NULL DEFAULT 0,
    total_failed INTEGER NOT NULL DEFAULT 0,
    last_sent_at TIMESTAMPTZ,
    last_error TEXT,
    last_error_at TIMESTAMPTZ,

    -- Audit
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_webhook_status CHECK (status IN ('active', 'disabled', 'error')),
    CONSTRAINT chk_webhook_severity CHECK (severity_threshold IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT unique_webhook_name UNIQUE (tenant_id, name)
);

-- =============================================================================
-- Webhook Deliveries (Delivery Log)
-- =============================================================================

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- References
    webhook_id UUID NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_id UUID,                                  -- Reference to notification event

    -- Request
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,

    -- Response
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    response_code INTEGER,
    response_body TEXT,
    response_headers JSONB,

    -- Retry
    attempt INTEGER NOT NULL DEFAULT 1,
    next_retry_at TIMESTAMPTZ,

    -- Error
    error_message TEXT,

    -- Timing
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ,
    duration_ms INTEGER,

    -- Constraints
    CONSTRAINT chk_delivery_status CHECK (status IN ('pending', 'success', 'failed', 'retrying'))
);

-- =============================================================================
-- Indexes
-- =============================================================================

-- Webhooks
CREATE INDEX IF NOT EXISTS idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_status ON webhooks(status);
CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(tenant_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_webhooks_events ON webhooks USING GIN(event_types);

-- Webhook deliveries
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook ON webhook_deliveries(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending ON webhook_deliveries(next_retry_at)
    WHERE status IN ('pending', 'retrying');
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_created ON webhook_deliveries(created_at DESC);

-- =============================================================================
-- Trigger
-- =============================================================================

CREATE TRIGGER update_webhooks_updated_at
    BEFORE UPDATE ON webhooks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE webhooks IS 'Outgoing webhook configuration for event notifications';
COMMENT ON COLUMN webhooks.event_types IS 'Events to send: finding.created, scan.completed, etc.';
COMMENT ON COLUMN webhooks.secret_encrypted IS 'HMAC signing secret for payload verification';

COMMENT ON TABLE webhook_deliveries IS 'Webhook delivery log and retry tracking';
