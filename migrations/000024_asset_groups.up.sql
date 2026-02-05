-- =============================================================================
-- Migration 024: Asset Groups
-- OpenCTEM OSS Edition
-- =============================================================================
-- Logical groupings of assets for CTEM scoping and organization.

CREATE TABLE IF NOT EXISTS asset_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    environment VARCHAR(20) NOT NULL DEFAULT 'development',
    criticality VARCHAR(20) NOT NULL DEFAULT 'medium',
    business_unit VARCHAR(255),
    owner VARCHAR(255),
    owner_email VARCHAR(255),
    tags TEXT[] NOT NULL DEFAULT '{}',

    -- Computed counts (updated by triggers/application)
    asset_count INTEGER NOT NULL DEFAULT 0,
    domain_count INTEGER NOT NULL DEFAULT 0,
    website_count INTEGER NOT NULL DEFAULT 0,
    service_count INTEGER NOT NULL DEFAULT 0,
    repository_count INTEGER NOT NULL DEFAULT 0,
    cloud_count INTEGER NOT NULL DEFAULT 0,
    credential_count INTEGER NOT NULL DEFAULT 0,

    -- Risk metrics
    risk_score INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_asset_groups_environment CHECK (environment IN ('production', 'staging', 'development', 'testing')),
    CONSTRAINT chk_asset_groups_criticality CHECK (criticality IN ('critical', 'high', 'medium', 'low')),
    CONSTRAINT chk_asset_groups_risk_score CHECK (risk_score >= 0 AND risk_score <= 100),
    CONSTRAINT unique_asset_group_name UNIQUE (tenant_id, name)
);

COMMENT ON TABLE asset_groups IS 'Logical groupings of assets for CTEM scoping';

-- Asset Group Members (Many-to-many junction table)
CREATE TABLE IF NOT EXISTS asset_group_members (
    asset_group_id UUID NOT NULL REFERENCES asset_groups(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_group_id, asset_id)
);

COMMENT ON TABLE asset_group_members IS 'Many-to-many relationship between asset groups and assets';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_asset_groups_tenant_id ON asset_groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_groups_environment ON asset_groups(environment);
CREATE INDEX IF NOT EXISTS idx_asset_groups_criticality ON asset_groups(criticality);
CREATE INDEX IF NOT EXISTS idx_asset_groups_business_unit ON asset_groups(business_unit);
CREATE INDEX IF NOT EXISTS idx_asset_groups_risk_score ON asset_groups(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_asset_groups_created_at ON asset_groups(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_groups_name_search ON asset_groups USING gin(to_tsvector('english', name || ' ' || COALESCE(description, '')));
CREATE INDEX IF NOT EXISTS idx_asset_groups_tags ON asset_groups USING gin(tags);

CREATE INDEX IF NOT EXISTS idx_asset_group_members_asset_id ON asset_group_members(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_group_members_group_id ON asset_group_members(asset_group_id);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_asset_groups_updated_at ON asset_groups;
CREATE TRIGGER trigger_asset_groups_updated_at
    BEFORE UPDATE ON asset_groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

