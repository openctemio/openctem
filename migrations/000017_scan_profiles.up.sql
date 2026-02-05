-- =============================================================================
-- Migration 017: Scan Profiles and Scan Sessions
-- OpenCTEM OSS Edition
-- =============================================================================

-- Scan Profiles (Reusable scan configurations)
CREATE TABLE IF NOT EXISTS scan_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    is_system BOOLEAN DEFAULT FALSE,
    tools_config JSONB DEFAULT '{}',
    intensity VARCHAR(20) DEFAULT 'medium',
    max_concurrent_scans INTEGER DEFAULT 5,
    timeout_seconds INTEGER DEFAULT 3600,
    quality_gate JSONB NOT NULL DEFAULT '{"enabled": false, "fail_on_critical": false, "fail_on_high": false, "max_critical": -1, "max_high": -1, "max_medium": -1, "max_total": -1, "new_findings_only": false, "baseline_branch": ""}',
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_scan_profiles_intensity CHECK (intensity IN ('low', 'medium', 'high')),
    CONSTRAINT scan_profiles_name_unique UNIQUE (tenant_id, name)
);

COMMENT ON TABLE scan_profiles IS 'Reusable scan configuration profiles';

-- Scan Sessions (Individual scan executions)
CREATE TABLE IF NOT EXISTS scan_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
    scanner_name VARCHAR(100) NOT NULL,
    scanner_version VARCHAR(50),
    scanner_type VARCHAR(50),
    asset_type VARCHAR(50) NOT NULL,
    asset_value VARCHAR(500) NOT NULL,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    commit_sha VARCHAR(40),
    branch VARCHAR(200),
    base_commit_sha VARCHAR(40),
    status VARCHAR(20) DEFAULT 'pending',
    error_message TEXT,
    findings_total INTEGER DEFAULT 0,
    findings_new INTEGER DEFAULT 0,
    findings_fixed INTEGER DEFAULT 0,
    findings_by_severity JSONB DEFAULT '{}',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    duration_ms BIGINT,
    scan_profile_id UUID REFERENCES scan_profiles(id) ON DELETE SET NULL,
    quality_gate_result JSONB,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_scan_sessions_scanner_type CHECK (scanner_type IS NULL OR scanner_type IN ('sast', 'sca', 'secret', 'container', 'iac', 'dast', 'recon')),
    CONSTRAINT chk_scan_sessions_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled'))
);

COMMENT ON TABLE scan_sessions IS 'Individual scan execution records';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Scan profiles indexes
CREATE INDEX IF NOT EXISTS idx_scan_profiles_tenant_id ON scan_profiles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_profiles_is_default ON scan_profiles(tenant_id, is_default) WHERE is_default = TRUE;
CREATE INDEX IF NOT EXISTS idx_scan_profiles_is_system ON scan_profiles(is_system) WHERE is_system = TRUE;
CREATE INDEX IF NOT EXISTS idx_scan_profiles_tags ON scan_profiles USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_scan_profiles_tools_config ON scan_profiles USING GIN(tools_config);
CREATE INDEX IF NOT EXISTS idx_scan_profiles_created_at ON scan_profiles(created_at);

-- Scan sessions indexes
CREATE INDEX IF NOT EXISTS idx_scan_sessions_tenant ON scan_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_agent ON scan_sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_asset ON scan_sessions(asset_id);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_status ON scan_sessions(status);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_scanner ON scan_sessions(scanner_name);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_asset_value ON scan_sessions(tenant_id, asset_type, asset_value);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_created ON scan_sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_baseline ON scan_sessions(tenant_id, asset_type, asset_value, branch, status, completed_at DESC) WHERE status = 'completed';
CREATE INDEX IF NOT EXISTS idx_scan_sessions_tenant_status ON scan_sessions(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_tenant_created ON scan_sessions(tenant_id, created_at DESC);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_scan_profiles_updated_at ON scan_profiles;
CREATE TRIGGER trigger_scan_profiles_updated_at
    BEFORE UPDATE ON scan_profiles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_scan_sessions_updated_at ON scan_sessions;
CREATE TRIGGER trigger_scan_sessions_updated_at
    BEFORE UPDATE ON scan_sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
