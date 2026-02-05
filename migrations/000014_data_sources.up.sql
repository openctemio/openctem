-- =============================================================================
-- Migration 014: Data Sources
-- OpenCTEM OSS Edition
-- =============================================================================

-- Custom type for source types
DO $$ BEGIN
    CREATE TYPE source_type AS ENUM ('integration', 'collector', 'scanner', 'manual');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE source_status AS ENUM ('pending', 'active', 'inactive', 'error', 'disabled');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Data Sources (Collectors, scanners, integrations registry)
CREATE TABLE IF NOT EXISTS data_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type source_type NOT NULL DEFAULT 'manual',
    description TEXT,
    version VARCHAR(50),
    hostname VARCHAR(255),
    ip_address INET,
    api_key_hash VARCHAR(255),
    api_key_prefix VARCHAR(12),
    api_key_last_used_at TIMESTAMPTZ,
    status source_status NOT NULL DEFAULT 'pending',
    last_seen_at TIMESTAMPTZ,
    last_error TEXT,
    error_count INTEGER DEFAULT 0,
    capabilities JSONB DEFAULT '[]',
    config JSONB DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    assets_collected BIGINT DEFAULT 0,
    findings_reported BIGINT DEFAULT 0,
    last_sync_at TIMESTAMPTZ,
    last_sync_duration_ms INTEGER,
    last_sync_assets_count INTEGER,
    last_sync_findings_count INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT data_sources_name_unique UNIQUE (tenant_id, name)
);

COMMENT ON TABLE data_sources IS 'Registry of data collectors, scanners, and integrations';

-- Asset Sources (Track which sources discovered each asset)
CREATE TABLE IF NOT EXISTS asset_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source_type source_type NOT NULL,
    source_id UUID REFERENCES data_sources(id) ON DELETE SET NULL,
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    source_ref VARCHAR(255),
    contributed_data JSONB DEFAULT '{}',
    confidence INTEGER DEFAULT 100,
    is_primary BOOLEAN DEFAULT FALSE,
    seen_count INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_asset_sources_confidence CHECK (confidence >= 0 AND confidence <= 100),
    CONSTRAINT asset_sources_unique UNIQUE (asset_id, source_type, source_id)
);

COMMENT ON TABLE asset_sources IS 'Track which data sources discovered each asset';

-- Finding Data Sources (Track which sources discovered each finding)
CREATE TABLE IF NOT EXISTS finding_data_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    source_type source_type NOT NULL,
    source_id UUID REFERENCES data_sources(id) ON DELETE SET NULL,
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    source_ref VARCHAR(255),
    scan_id VARCHAR(255),
    contributed_data JSONB DEFAULT '{}',
    confidence INTEGER DEFAULT 100,
    is_primary BOOLEAN DEFAULT FALSE,
    seen_count INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_finding_data_sources_confidence CHECK (confidence >= 0 AND confidence <= 100),
    CONSTRAINT finding_data_sources_unique UNIQUE (finding_id, source_type, source_id)
);

COMMENT ON TABLE finding_data_sources IS 'Track which data sources discovered each finding';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Data sources indexes
CREATE INDEX IF NOT EXISTS idx_data_sources_tenant ON data_sources(tenant_id);
CREATE INDEX IF NOT EXISTS idx_data_sources_tenant_type ON data_sources(tenant_id, type);
CREATE INDEX IF NOT EXISTS idx_data_sources_tenant_status ON data_sources(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_data_sources_api_key_prefix ON data_sources(api_key_prefix) WHERE api_key_prefix IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_data_sources_last_seen ON data_sources(last_seen_at) WHERE status = 'active';

-- Asset sources indexes
CREATE INDEX IF NOT EXISTS idx_asset_sources_asset ON asset_sources(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_sources_source ON asset_sources(source_id) WHERE source_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_sources_source_type ON asset_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_asset_sources_primary ON asset_sources(asset_id) WHERE is_primary = TRUE;
CREATE INDEX IF NOT EXISTS idx_asset_sources_last_seen ON asset_sources(last_seen_at);

-- Finding data sources indexes
CREATE INDEX IF NOT EXISTS idx_finding_data_sources_finding ON finding_data_sources(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_data_sources_source ON finding_data_sources(source_id) WHERE source_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_finding_data_sources_source_type ON finding_data_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_finding_data_sources_primary ON finding_data_sources(finding_id) WHERE is_primary = TRUE;
CREATE INDEX IF NOT EXISTS idx_finding_data_sources_last_seen ON finding_data_sources(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_finding_data_sources_scan_id ON finding_data_sources(scan_id) WHERE scan_id IS NOT NULL;

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_data_sources_updated_at ON data_sources;
CREATE TRIGGER trigger_data_sources_updated_at
    BEFORE UPDATE ON data_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_asset_sources_updated_at ON asset_sources;
CREATE TRIGGER trigger_asset_sources_updated_at
    BEFORE UPDATE ON asset_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_finding_data_sources_updated_at ON finding_data_sources;
CREATE TRIGGER trigger_finding_data_sources_updated_at
    BEFORE UPDATE ON finding_data_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Foreign Key: assets.source_id -> data_sources.id
-- (Added here since data_sources is created in this migration)
-- =============================================================================

DO $$ BEGIN
    ALTER TABLE assets
        ADD CONSTRAINT assets_source_id_fkey
        FOREIGN KEY (source_id) REFERENCES data_sources(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
