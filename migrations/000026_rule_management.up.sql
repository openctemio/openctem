-- =============================================================================
-- Migration 026: Rule Management System
-- OpenCTEM OSS Edition
-- =============================================================================
-- Supports custom rules/templates for security scanning tools (Semgrep, Nuclei, etc.)
-- Tenants can add their own rule sources (Git repos, HTTP URLs) alongside platform defaults.

-- Rule Sources: Where to fetch rules from
CREATE TABLE IF NOT EXISTS rule_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_id UUID REFERENCES tools(id) ON DELETE SET NULL,

    -- Basic info
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Source configuration
    source_type VARCHAR(20) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    -- Git:   { "url": "...", "branch": "main", "path": "rules/", "auth_type": "none|ssh|token", "credentials_id": "..." }
    -- HTTP:  { "url": "...", "auth_type": "none|basic|bearer", "credentials_id": "..." }
    -- Local: { "path": "/rules/custom/" }

    -- Credentials reference
    credentials_id UUID REFERENCES credentials(id) ON DELETE SET NULL,

    -- Sync configuration
    sync_enabled BOOLEAN NOT NULL DEFAULT true,
    sync_interval_minutes INTEGER NOT NULL DEFAULT 60,

    -- Sync status
    last_sync_at TIMESTAMPTZ,
    last_sync_status VARCHAR(20) DEFAULT 'pending',
    last_sync_error TEXT,
    last_sync_duration_ms INTEGER,
    content_hash VARCHAR(64),

    -- Rule count from last sync
    rule_count INTEGER DEFAULT 0,

    -- Priority for merge order (higher = applied later)
    priority INTEGER NOT NULL DEFAULT 100,

    -- Platform default source (managed by system)
    is_platform_default BOOLEAN NOT NULL DEFAULT false,

    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_rule_sources_type CHECK (source_type IN ('git', 'http', 'local')),
    CONSTRAINT chk_rule_sources_sync_status CHECK (last_sync_status IN ('pending', 'syncing', 'success', 'failed'))
);

COMMENT ON TABLE rule_sources IS 'Sources for security rules (Git repos, HTTP URLs, etc.)';

-- Individual Rules: Indexed metadata for UI/filtering
CREATE TABLE IF NOT EXISTS rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES rule_sources(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_id UUID REFERENCES tools(id) ON DELETE SET NULL,

    -- Rule identification (tool-specific)
    rule_id VARCHAR(500) NOT NULL,
    name VARCHAR(500),

    -- Classification
    severity VARCHAR(20),
    category VARCHAR(100),
    subcategory VARCHAR(100),
    tags TEXT[] DEFAULT '{}',

    -- Metadata
    description TEXT,
    recommendation TEXT,
    "references" TEXT[] DEFAULT '{}',
    cwe_ids TEXT[] DEFAULT '{}',
    owasp_ids TEXT[] DEFAULT '{}',

    -- File info within source
    file_path VARCHAR(500),
    content_hash VARCHAR(64),

    -- Additional metadata
    metadata JSONB DEFAULT '{}',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_rules_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
    CONSTRAINT unique_rule_source UNIQUE (source_id, rule_id)
);

COMMENT ON TABLE rules IS 'Individual rules indexed from sources for UI/filtering';

-- Rule Overrides: Tenant-specific rule enable/disable
CREATE TABLE IF NOT EXISTS rule_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_id UUID REFERENCES tools(id) ON DELETE CASCADE,

    -- What to override
    rule_pattern VARCHAR(500) NOT NULL,
    is_pattern BOOLEAN NOT NULL DEFAULT false,

    -- Override settings
    enabled BOOLEAN NOT NULL,
    severity_override VARCHAR(20),

    -- Optional scope
    asset_group_id UUID REFERENCES asset_groups(id) ON DELETE CASCADE,
    scan_profile_id UUID REFERENCES scan_profiles(id) ON DELETE CASCADE,

    -- Audit
    reason TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    CONSTRAINT chk_rule_overrides_severity CHECK (severity_override IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT unique_rule_override UNIQUE (tenant_id, tool_id, rule_pattern, asset_group_id, scan_profile_id)
);

COMMENT ON TABLE rule_overrides IS 'Tenant-specific rule enable/disable configuration';

-- Rule Bundles: Pre-compiled rule packages for agents
CREATE TABLE IF NOT EXISTS rule_bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_id UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,

    -- Version info
    version VARCHAR(50) NOT NULL,
    content_hash VARCHAR(64) NOT NULL UNIQUE,

    -- Bundle statistics
    rule_count INTEGER NOT NULL DEFAULT 0,
    source_count INTEGER NOT NULL DEFAULT 0,
    size_bytes BIGINT NOT NULL DEFAULT 0,

    -- Sources included
    source_ids UUID[] NOT NULL DEFAULT '{}',
    source_hashes JSONB NOT NULL DEFAULT '{}',

    -- Storage
    storage_path VARCHAR(500) NOT NULL,

    -- Build status
    status VARCHAR(20) NOT NULL DEFAULT 'building',
    build_error TEXT,
    build_started_at TIMESTAMPTZ,
    build_completed_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,

    CONSTRAINT chk_rule_bundles_status CHECK (status IN ('building', 'ready', 'failed', 'expired'))
);

COMMENT ON TABLE rule_bundles IS 'Pre-compiled rule packages for agent download';

-- Rule Sync History: Audit trail
CREATE TABLE IF NOT EXISTS rule_sync_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL REFERENCES rule_sources(id) ON DELETE CASCADE,

    status VARCHAR(20) NOT NULL,

    -- Stats
    rules_added INTEGER DEFAULT 0,
    rules_updated INTEGER DEFAULT 0,
    rules_removed INTEGER DEFAULT 0,
    duration_ms INTEGER,

    -- Error info
    error_message TEXT,
    error_details JSONB,

    -- Hashes
    previous_hash VARCHAR(64),
    new_hash VARCHAR(64),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_rule_sync_status CHECK (status IN ('started', 'success', 'failed'))
);

COMMENT ON TABLE rule_sync_history IS 'Audit trail of rule synchronization';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Rule sources indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_rule_sources_tenant_tool_name ON rule_sources(tenant_id, COALESCE(tool_id, '00000000-0000-0000-0000-000000000000'), name);
CREATE INDEX IF NOT EXISTS idx_rule_sources_tenant ON rule_sources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rule_sources_tool ON rule_sources(tool_id);
CREATE INDEX IF NOT EXISTS idx_rule_sources_enabled ON rule_sources(enabled);
CREATE INDEX IF NOT EXISTS idx_rule_sources_sync_status ON rule_sources(last_sync_status);

-- Rules indexes
CREATE INDEX IF NOT EXISTS idx_rules_tenant ON rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rules_source ON rules(source_id);
CREATE INDEX IF NOT EXISTS idx_rules_tool ON rules(tool_id);
CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules(severity);
CREATE INDEX IF NOT EXISTS idx_rules_category ON rules(category);
CREATE INDEX IF NOT EXISTS idx_rules_tags ON rules USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_rules_rule_id ON rules(rule_id);

-- Rule overrides indexes
CREATE INDEX IF NOT EXISTS idx_rule_overrides_tenant ON rule_overrides(tenant_id);
CREATE INDEX IF NOT EXISTS idx_rule_overrides_tool ON rule_overrides(tool_id);
CREATE INDEX IF NOT EXISTS idx_rule_overrides_enabled ON rule_overrides(enabled);
CREATE INDEX IF NOT EXISTS idx_rule_overrides_expires ON rule_overrides(expires_at) WHERE expires_at IS NOT NULL;

-- Rule bundles indexes
CREATE INDEX IF NOT EXISTS idx_rule_bundles_tenant_tool ON rule_bundles(tenant_id, tool_id);
CREATE INDEX IF NOT EXISTS idx_rule_bundles_status ON rule_bundles(status);
CREATE INDEX IF NOT EXISTS idx_rule_bundles_expires ON rule_bundles(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_rule_bundles_latest ON rule_bundles(tenant_id, tool_id, created_at DESC) WHERE status = 'ready';

-- Rule sync history indexes
CREATE INDEX IF NOT EXISTS idx_rule_sync_history_source ON rule_sync_history(source_id);
CREATE INDEX IF NOT EXISTS idx_rule_sync_history_created ON rule_sync_history(created_at);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_rule_sources_updated_at ON rule_sources;
CREATE TRIGGER trigger_rule_sources_updated_at
    BEFORE UPDATE ON rule_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_rules_updated_at ON rules;
CREATE TRIGGER trigger_rules_updated_at
    BEFORE UPDATE ON rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_rule_overrides_updated_at ON rule_overrides;
CREATE TRIGGER trigger_rule_overrides_updated_at
    BEFORE UPDATE ON rule_overrides
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

