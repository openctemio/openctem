-- =============================================================================
-- Migration 027: Scope Configuration
-- OpenCTEM OSS Edition
-- =============================================================================
-- Defines what assets/patterns are IN-SCOPE for scanning and what should be EXCLUDED.

-- Scope Targets: Define what assets/patterns are IN-SCOPE for scanning
CREATE TABLE IF NOT EXISTS scope_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_type VARCHAR(50) NOT NULL,
    pattern VARCHAR(500) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 0,
    status VARCHAR(20) DEFAULT 'active',
    tags TEXT[] DEFAULT '{}',
    created_by VARCHAR(200),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT chk_scope_target_type CHECK (target_type IN (
        'domain', 'subdomain', 'ip_address', 'ip_range', 'cidr',
        'url', 'api', 'website', 'repository', 'project',
        'cloud_account', 'cloud_resource', 'container', 'host',
        'database', 'network', 'certificate', 'mobile_app', 'email_domain'
    )),
    CONSTRAINT chk_scope_target_status CHECK (status IN ('active', 'inactive')),
    CONSTRAINT unique_scope_target UNIQUE (tenant_id, target_type, pattern)
);

COMMENT ON TABLE scope_targets IS 'Defines what assets/patterns are IN-SCOPE for scanning';

-- Scope Exclusions: Define what should be EXCLUDED from scanning
CREATE TABLE IF NOT EXISTS scope_exclusions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    exclusion_type VARCHAR(50) NOT NULL,
    pattern VARCHAR(500) NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    expires_at TIMESTAMPTZ,
    approved_by VARCHAR(200),
    approved_at TIMESTAMPTZ,
    created_by VARCHAR(200),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT chk_scope_exclusion_type CHECK (exclusion_type IN (
        'domain', 'subdomain', 'ip_address', 'ip_range', 'cidr',
        'url', 'path', 'repository', 'finding_type', 'scanner'
    )),
    CONSTRAINT chk_scope_exclusion_status CHECK (status IN ('active', 'inactive', 'expired')),
    CONSTRAINT unique_scope_exclusion UNIQUE (tenant_id, exclusion_type, pattern)
);

COMMENT ON TABLE scope_exclusions IS 'Defines what should be EXCLUDED from scanning';

-- Scan Schedules: Automated scan configurations
CREATE TABLE IF NOT EXISTS scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    scan_type VARCHAR(50) NOT NULL,
    target_scope VARCHAR(20) DEFAULT 'all',
    target_ids UUID[] DEFAULT '{}',
    target_tags TEXT[] DEFAULT '{}',
    scanner_configs JSONB DEFAULT '{}',
    schedule_type VARCHAR(20) NOT NULL,
    cron_expression VARCHAR(100),
    interval_hours INTEGER,
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMPTZ,
    last_run_status VARCHAR(20),
    next_run_at TIMESTAMPTZ,
    notify_on_completion BOOLEAN DEFAULT true,
    notify_on_findings BOOLEAN DEFAULT true,
    notification_channels JSONB DEFAULT '["email"]',
    created_by VARCHAR(200),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT chk_scan_schedule_type CHECK (scan_type IN (
        'full', 'incremental', 'targeted', 'vulnerability',
        'compliance', 'secret', 'sast', 'dast', 'sca'
    )),
    CONSTRAINT chk_scan_schedule_timing CHECK (schedule_type IN ('cron', 'interval', 'manual')),
    CONSTRAINT chk_scan_schedule_target CHECK (target_scope IN ('all', 'selected', 'tag'))
);

COMMENT ON TABLE scan_schedules IS 'Automated scan configurations with scheduling';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Scope targets indexes
CREATE INDEX IF NOT EXISTS idx_scope_targets_tenant ON scope_targets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scope_targets_active ON scope_targets(tenant_id, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_scope_targets_type ON scope_targets(tenant_id, target_type);

-- Scope exclusions indexes
CREATE INDEX IF NOT EXISTS idx_scope_exclusions_tenant ON scope_exclusions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scope_exclusions_active ON scope_exclusions(tenant_id, status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_scope_exclusions_expires ON scope_exclusions(expires_at) WHERE expires_at IS NOT NULL AND status = 'active';

-- Scan schedules indexes
CREATE INDEX IF NOT EXISTS idx_scan_schedules_tenant ON scan_schedules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_schedules_enabled ON scan_schedules(tenant_id, enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_scan_schedules_next_run ON scan_schedules(next_run_at) WHERE enabled = true;

-- =============================================================================
-- Functions
-- =============================================================================

-- Function to auto-expire exclusions
CREATE OR REPLACE FUNCTION expire_scope_exclusions()
RETURNS void AS $$
BEGIN
    UPDATE scope_exclusions
    SET status = 'expired', updated_at = NOW()
    WHERE status = 'active'
      AND expires_at IS NOT NULL
      AND expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION expire_scope_exclusions() IS 'Marks expired scope exclusions as expired';

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_scope_targets_updated_at ON scope_targets;
CREATE TRIGGER trigger_scope_targets_updated_at
    BEFORE UPDATE ON scope_targets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_scope_exclusions_updated_at ON scope_exclusions;
CREATE TRIGGER trigger_scope_exclusions_updated_at
    BEFORE UPDATE ON scope_exclusions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_scan_schedules_updated_at ON scan_schedules;
CREATE TRIGGER trigger_scan_schedules_updated_at
    BEFORE UPDATE ON scan_schedules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

