-- =============================================================================
-- Migration 028: Exposure Events (CTEM Foundation)
-- OpenCTEM OSS Edition
-- =============================================================================
-- Exposure Events track attack surface changes that are NOT vulnerabilities.
-- Examples: open ports, public buckets, exposed APIs, certificate expiry, etc.

CREATE TABLE IF NOT EXISTS exposure_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,

    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    state VARCHAR(20) NOT NULL DEFAULT 'active',
    title VARCHAR(500) NOT NULL,
    description TEXT,
    details JSONB NOT NULL DEFAULT '{}',
    fingerprint VARCHAR(64) NOT NULL,
    source VARCHAR(100) NOT NULL,

    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    resolution_notes TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_exposure_events_type CHECK (
        event_type IN (
            'port_open', 'port_closed', 'service_detected', 'service_changed',
            'subdomain_discovered', 'subdomain_removed', 'certificate_expiring',
            'certificate_expired', 'bucket_public', 'bucket_private',
            'repo_public', 'repo_private', 'api_exposed', 'api_removed',
            'credential_leaked', 'sensitive_data_exposed', 'misconfiguration',
            'dns_change', 'ssl_issue', 'header_missing', 'custom'
        )
    ),
    CONSTRAINT chk_exposure_events_severity CHECK (
        severity IN ('critical', 'high', 'medium', 'low', 'info')
    ),
    CONSTRAINT chk_exposure_events_state CHECK (
        state IN ('active', 'resolved', 'accepted', 'false_positive')
    ),
    CONSTRAINT uq_exposure_events_fingerprint UNIQUE (tenant_id, fingerprint)
);

COMMENT ON TABLE exposure_events IS 'Exposure events track attack surface changes (non-vulnerability)';

-- Exposure State History: Audit trail for state changes
CREATE TABLE IF NOT EXISTS exposure_state_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    exposure_event_id UUID NOT NULL REFERENCES exposure_events(id) ON DELETE CASCADE,
    previous_state VARCHAR(20) NOT NULL,
    new_state VARCHAR(20) NOT NULL,
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_exposure_state_history_prev CHECK (
        previous_state IN ('active', 'resolved', 'accepted', 'false_positive')
    ),
    CONSTRAINT chk_exposure_state_history_new CHECK (
        new_state IN ('active', 'resolved', 'accepted', 'false_positive')
    )
);

COMMENT ON TABLE exposure_state_history IS 'Audit trail for exposure event state changes';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Exposure events indexes
CREATE INDEX IF NOT EXISTS idx_exposure_events_tenant ON exposure_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_exposure_events_asset ON exposure_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_exposure_events_event_type ON exposure_events(event_type);
CREATE INDEX IF NOT EXISTS idx_exposure_events_severity ON exposure_events(severity);
CREATE INDEX IF NOT EXISTS idx_exposure_events_state ON exposure_events(state);
CREATE INDEX IF NOT EXISTS idx_exposure_events_fingerprint ON exposure_events(fingerprint);
CREATE INDEX IF NOT EXISTS idx_exposure_events_source ON exposure_events(source);
CREATE INDEX IF NOT EXISTS idx_exposure_events_first_seen ON exposure_events(first_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_exposure_events_last_seen ON exposure_events(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_exposure_events_created_at ON exposure_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_exposure_events_details ON exposure_events USING GIN(details);

-- Composite indexes for common queries
CREATE INDEX IF NOT EXISTS idx_exposure_events_tenant_state ON exposure_events(tenant_id, state);
CREATE INDEX IF NOT EXISTS idx_exposure_events_tenant_severity ON exposure_events(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_exposure_events_tenant_type ON exposure_events(tenant_id, event_type);

-- Exposure state history indexes
CREATE INDEX IF NOT EXISTS idx_exposure_state_history_event ON exposure_state_history(exposure_event_id);
CREATE INDEX IF NOT EXISTS idx_exposure_state_history_changed_by ON exposure_state_history(changed_by);
CREATE INDEX IF NOT EXISTS idx_exposure_state_history_created ON exposure_state_history(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_exposure_state_history_new_state ON exposure_state_history(new_state);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_exposure_events_updated_at ON exposure_events;
CREATE TRIGGER trigger_exposure_events_updated_at
    BEFORE UPDATE ON exposure_events
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

