-- =============================================================================
-- Migration 008: Assets
-- OpenCTEM OSS Edition
-- =============================================================================

-- Assets (Core table for all asset types)
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(50) NOT NULL,
    criticality VARCHAR(20) NOT NULL DEFAULT 'medium',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    description TEXT,
    scope VARCHAR(20) NOT NULL DEFAULT 'internal',
    exposure VARCHAR(20) NOT NULL DEFAULT 'unknown',
    risk_score INTEGER NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    properties JSONB NOT NULL DEFAULT '{}',
    provider VARCHAR(50),
    external_id VARCHAR(255),
    sync_status VARCHAR(20) NOT NULL DEFAULT 'synced',
    last_synced_at TIMESTAMPTZ,
    sync_error TEXT,
    classification VARCHAR(50),
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    parent_id UUID REFERENCES assets(id) ON DELETE SET NULL,

    -- CTEM fields
    business_unit VARCHAR(100),
    data_classification VARCHAR(50),
    compliance_requirements TEXT[],
    compliance_scope TEXT[] DEFAULT '{}',
    last_assessment_at TIMESTAMPTZ,
    next_assessment_at TIMESTAMPTZ,

    -- CTEM data sensitivity
    pii_data_exposed BOOLEAN DEFAULT false,
    phi_data_exposed BOOLEAN DEFAULT false,
    regulatory_owner_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- CTEM exposure tracking
    is_internet_accessible BOOLEAN DEFAULT false,
    exposure_changed_at TIMESTAMPTZ,
    last_exposure_level VARCHAR(50),

    -- Data Source tracking
    source_type VARCHAR(50) DEFAULT 'manual',
    source_id UUID,
    source_ref VARCHAR(255),
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    discovery_source VARCHAR(50),
    discovery_tool VARCHAR(50),

    -- Integration tracking
    integration_id UUID,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_assets_type CHECK (
        asset_type IN (
            'domain', 'subdomain', 'certificate', 'ip_address',
            'website', 'api', 'mobile_app', 'service', 'web_application',
            'repository', 'code_repo',
            'cloud_account', 'compute', 'storage', 'serverless', 'container_registry',
            'host', 'server', 'container', 'kubernetes_cluster', 'kubernetes_namespace',
            'database', 'data_store', 's3_bucket',
            'network', 'vpc', 'subnet', 'load_balancer', 'firewall',
            'iam_user', 'iam_role', 'service_account',
            'application', 'endpoint', 'cloud', 'unclassified', 'other'
        )
    ),
    CONSTRAINT chk_assets_criticality CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT chk_assets_status CHECK (status IN ('active', 'inactive', 'archived')),
    CONSTRAINT chk_assets_scope CHECK (scope IN ('internal', 'external', 'cloud', 'partner', 'vendor', 'shadow')),
    CONSTRAINT chk_assets_exposure CHECK (exposure IN ('public', 'restricted', 'private', 'isolated', 'unknown')),
    CONSTRAINT chk_assets_risk_score CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT chk_assets_sync_status CHECK (sync_status IN ('synced', 'pending', 'syncing', 'error', 'disabled')),
    CONSTRAINT chk_assets_data_classification CHECK (data_classification IS NULL OR data_classification IN ('public', 'internal', 'confidential', 'restricted', 'secret')),
    CONSTRAINT chk_assets_last_exposure_level CHECK (last_exposure_level IS NULL OR last_exposure_level IN ('public', 'restricted', 'private', 'isolated', 'unknown')),
    CONSTRAINT chk_assets_source_type CHECK (source_type IS NULL OR source_type IN ('manual', 'integration', 'discovery', 'import', 'api', 'agent', 'scan'))
);

COMMENT ON TABLE assets IS 'Core asset inventory table';
COMMENT ON COLUMN assets.data_classification IS 'CTEM: Data sensitivity level (public, internal, confidential, restricted, secret)';
COMMENT ON COLUMN assets.compliance_scope IS 'CTEM: Applicable compliance frameworks (PCI-DSS, HIPAA, SOC2, etc.)';
COMMENT ON COLUMN assets.pii_data_exposed IS 'CTEM: True if asset handles/exposes PII data';
COMMENT ON COLUMN assets.phi_data_exposed IS 'CTEM: True if asset handles/exposes PHI data';
COMMENT ON COLUMN assets.is_internet_accessible IS 'CTEM: True if asset is accessible from internet';
COMMENT ON COLUMN assets.exposure_changed_at IS 'CTEM: When the exposure level last changed';
COMMENT ON COLUMN assets.last_exposure_level IS 'CTEM: Previous exposure level before change';

-- Asset Owners (Group ownership of assets)
CREATE TABLE IF NOT EXISTS asset_owners (
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    ownership_type VARCHAR(50) DEFAULT 'primary',
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id),

    PRIMARY KEY (asset_id, group_id),
    CONSTRAINT chk_ownership_type CHECK (ownership_type IN ('primary', 'secondary', 'stakeholder', 'informed'))
);

COMMENT ON TABLE asset_owners IS 'Links groups to assets they own/manage';

-- Note: asset_groups and asset_group_members are created in migration 000024_asset_groups.up.sql

-- =============================================================================
-- Indexes
-- =============================================================================

-- Assets indexes
CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_name ON assets(name);
CREATE INDEX IF NOT EXISTS idx_assets_asset_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_scope ON assets(scope);
CREATE INDEX IF NOT EXISTS idx_assets_exposure ON assets(exposure);
CREATE INDEX IF NOT EXISTS idx_assets_risk_score ON assets(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON assets USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_assets_metadata ON assets USING GIN(metadata);
CREATE INDEX IF NOT EXISTS idx_assets_properties ON assets USING GIN(properties);
CREATE INDEX IF NOT EXISTS idx_assets_provider ON assets(provider);
CREATE INDEX IF NOT EXISTS idx_assets_external_id ON assets(external_id);
CREATE INDEX IF NOT EXISTS idx_assets_sync_status ON assets(sync_status);
CREATE INDEX IF NOT EXISTS idx_assets_owner_id ON assets(owner_id);
CREATE INDEX IF NOT EXISTS idx_assets_parent_id ON assets(parent_id);
CREATE INDEX IF NOT EXISTS idx_assets_created_at ON assets(created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_name_tenant_unique ON assets(tenant_id, name);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_type ON assets(tenant_id, asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_status ON assets(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_risk ON assets(tenant_id, risk_score DESC);

-- CTEM indexes
CREATE INDEX IF NOT EXISTS idx_assets_compliance ON assets USING GIN (compliance_scope);
CREATE INDEX IF NOT EXISTS idx_assets_data_classification ON assets(data_classification) WHERE data_classification IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_pii ON assets(tenant_id) WHERE pii_data_exposed = true;
CREATE INDEX IF NOT EXISTS idx_assets_phi ON assets(tenant_id) WHERE phi_data_exposed = true;
CREATE INDEX IF NOT EXISTS idx_assets_internet ON assets(tenant_id) WHERE is_internet_accessible = true;
CREATE INDEX IF NOT EXISTS idx_assets_exposure_changed ON assets(exposure_changed_at DESC) WHERE exposure_changed_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_regulatory_owner ON assets(regulatory_owner_id) WHERE regulatory_owner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_tenant_compliance ON assets(tenant_id, data_classification) WHERE data_classification IS NOT NULL;

-- Data source and integration indexes
CREATE INDEX IF NOT EXISTS idx_assets_source_type ON assets(source_type);
CREATE INDEX IF NOT EXISTS idx_assets_source_id ON assets(source_id) WHERE source_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_integration_id ON assets(integration_id) WHERE integration_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assets_discovered_at ON assets(discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_assets_discovery_source ON assets(discovery_source) WHERE discovery_source IS NOT NULL;

-- Asset owners indexes
CREATE INDEX IF NOT EXISTS idx_asset_owners_group ON asset_owners(group_id);
CREATE INDEX IF NOT EXISTS idx_asset_owners_asset ON asset_owners(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_owners_group_asset ON asset_owners(group_id, asset_id);

-- Note: asset_groups and asset_group_members indexes are in migration 000024_asset_groups.up.sql

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_assets_updated_at ON assets;
CREATE TRIGGER trigger_assets_updated_at
    BEFORE UPDATE ON assets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Note: asset_groups trigger is in migration 000024_asset_groups.up.sql
