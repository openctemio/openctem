-- =============================================================================
-- Migration 020: Notifications (Outbox and Events)
-- OpenCTEM OSS Edition
-- =============================================================================

-- Event Types (Dynamic notification event configuration)
CREATE TABLE IF NOT EXISTS event_types (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    module_id VARCHAR(50) REFERENCES modules(id) ON DELETE SET NULL,
    default_severity VARCHAR(20) DEFAULT 'info',
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE event_types IS 'Available notification event types';

-- Notification Outbox (Transactional outbox pattern)
CREATE TABLE IF NOT EXISTS notification_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    aggregate_type VARCHAR(100),
    aggregate_id UUID,
    title VARCHAR(500) NOT NULL,
    body TEXT,
    severity VARCHAR(20) DEFAULT 'info',
    url VARCHAR(2000),
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) DEFAULT 'pending',
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    last_error TEXT,
    scheduled_at TIMESTAMPTZ DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(100),
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_notification_outbox_status CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'dead')),
    CONSTRAINT chk_notification_outbox_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'none')),
    CONSTRAINT chk_notification_outbox_retry CHECK (retry_count >= 0 AND retry_count <= max_retries + 1)
);

COMMENT ON TABLE notification_outbox IS 'Transactional outbox for reliable notification delivery';

-- Notification Events (Permanent archive)
CREATE TABLE IF NOT EXISTS notification_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    outbox_id UUID,
    event_type VARCHAR(100) NOT NULL,
    aggregate_type VARCHAR(100),
    aggregate_id UUID,
    title VARCHAR(500) NOT NULL,
    body TEXT,
    severity VARCHAR(20),
    url VARCHAR(2000),
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL,
    integrations_total INTEGER DEFAULT 0,
    integrations_matched INTEGER DEFAULT 0,
    integrations_succeeded INTEGER DEFAULT 0,
    integrations_failed INTEGER DEFAULT 0,
    send_results JSONB DEFAULT '[]',
    last_error TEXT,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT chk_notification_events_status CHECK (status IN ('completed', 'failed', 'skipped'))
);

COMMENT ON TABLE notification_events IS 'Permanent archive of sent notifications';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Event types indexes
CREATE INDEX IF NOT EXISTS idx_event_types_category ON event_types(category);
CREATE INDEX IF NOT EXISTS idx_event_types_module ON event_types(module_id);
CREATE INDEX IF NOT EXISTS idx_event_types_active ON event_types(is_active) WHERE is_active = TRUE;

-- Notification outbox indexes
CREATE INDEX IF NOT EXISTS idx_notification_outbox_pending ON notification_outbox(scheduled_at ASC, created_at ASC) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_notification_outbox_locked ON notification_outbox(locked_at ASC) WHERE status = 'processing' AND locked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notification_outbox_cleanup ON notification_outbox(processed_at ASC) WHERE status IN ('completed', 'dead');
CREATE INDEX IF NOT EXISTS idx_notification_outbox_tenant ON notification_outbox(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_outbox_aggregate ON notification_outbox(aggregate_type, aggregate_id) WHERE aggregate_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notification_outbox_status ON notification_outbox(status);

-- Notification events indexes
CREATE INDEX IF NOT EXISTS idx_notification_events_tenant ON notification_events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_events_type ON notification_events(event_type);
CREATE INDEX IF NOT EXISTS idx_notification_events_aggregate ON notification_events(aggregate_type, aggregate_id) WHERE aggregate_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notification_events_created ON notification_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notification_events_status ON notification_events(status);
CREATE INDEX IF NOT EXISTS idx_notification_events_processed ON notification_events(processed_at DESC);

-- =============================================================================
-- Seed Event Types
-- =============================================================================

INSERT INTO event_types (id, name, description, category, module_id, default_severity) VALUES
    ('finding.created', 'New Finding', 'New security finding detected', 'findings', 'findings', 'high'),
    ('finding.status_changed', 'Finding Status Changed', 'Finding status was updated', 'findings', 'findings', 'info'),
    ('finding.resolved', 'Finding Resolved', 'Finding was resolved', 'findings', 'findings', 'info'),
    ('scan.started', 'Scan Started', 'Security scan started', 'scans', 'scans', 'info'),
    ('scan.completed', 'Scan Completed', 'Security scan completed', 'scans', 'scans', 'info'),
    ('scan.failed', 'Scan Failed', 'Security scan failed', 'scans', 'scans', 'high'),
    ('asset.created', 'New Asset', 'New asset discovered', 'assets', 'assets', 'info'),
    ('asset.exposure_changed', 'Asset Exposure Changed', 'Asset exposure level changed', 'assets', 'assets', 'medium'),
    ('exposure.created', 'New Exposure', 'New security exposure detected', 'exposures', 'exposures', 'high'),
    ('agent.offline', 'Agent Offline', 'Scanning agent went offline', 'agents', 'agents', 'high'),
    ('agent.error', 'Agent Error', 'Scanning agent encountered error', 'agents', 'agents', 'medium')
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    module_id = EXCLUDED.module_id,
    default_severity = EXCLUDED.default_severity;

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_notification_outbox_updated_at ON notification_outbox;
CREATE TRIGGER trigger_notification_outbox_updated_at
    BEFORE UPDATE ON notification_outbox
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
