-- =============================================================================
-- Migration 010: Components (SBOM/Dependencies)
-- OpenCTEM OSS Edition
-- =============================================================================

-- Asset Components (Dependencies/SBOM)
CREATE TABLE IF NOT EXISTS asset_components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    component_id UUID,
    branch_id UUID REFERENCES repository_branches(id) ON DELETE SET NULL,
    path VARCHAR(1000),
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    ecosystem VARCHAR(50) NOT NULL,
    package_manager VARCHAR(50),
    namespace VARCHAR(255),
    manifest_file VARCHAR(255),
    manifest_path VARCHAR(500),
    dependency_type VARCHAR(50) DEFAULT 'direct',
    license VARCHAR(255),
    purl VARCHAR(500),
    cpe VARCHAR(500),
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(50) DEFAULT 'active',

    -- Dependency graph fields
    parent_component_id UUID REFERENCES asset_components(id) ON DELETE SET NULL,
    depth INTEGER DEFAULT 0,
    is_direct BOOLEAN DEFAULT TRUE,

    -- Risk fields
    has_known_vulnerabilities BOOLEAN DEFAULT FALSE,
    highest_severity VARCHAR(20),
    risk_score INTEGER DEFAULT 0,

    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_ecosystem CHECK (ecosystem IN (
        'npm', 'maven', 'pypi', 'go', 'cargo', 'nuget', 'rubygems',
        'composer', 'cocoapods', 'hex', 'pub', 'swiftpm', 'cran',
        'gradle', 'sbt', 'packagist', 'homebrew', 'other'
    )),
    CONSTRAINT chk_dependency_type CHECK (dependency_type IN ('direct', 'transitive', 'dev', 'optional', 'peer', 'build')),
    CONSTRAINT chk_component_status CHECK (status IN ('active', 'deprecated', 'end_of_life', 'unknown')),
    CONSTRAINT unique_component UNIQUE (tenant_id, asset_id, name, version, branch_id)
);

COMMENT ON TABLE asset_components IS 'Software components and dependencies (SBOM)';

-- Licenses (for license compliance)
CREATE TABLE IF NOT EXISTS licenses (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    spdx_id VARCHAR(100),
    url VARCHAR(500),
    is_osi_approved BOOLEAN DEFAULT FALSE,
    is_fsf_libre BOOLEAN DEFAULT FALSE,
    is_deprecated BOOLEAN DEFAULT FALSE,
    category VARCHAR(50),
    risk VARCHAR(20) DEFAULT 'unknown',
    description TEXT,
    permissions TEXT[],
    conditions TEXT[],
    limitations TEXT[],
    created_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT chk_license_category CHECK (category IN ('permissive', 'copyleft', 'weak_copyleft', 'proprietary', 'public_domain', 'unknown')),
    CONSTRAINT chk_license_risk CHECK (risk IN ('low', 'medium', 'high', 'critical', 'unknown'))
);

COMMENT ON TABLE licenses IS 'Software license definitions for compliance';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_asset_components_tenant ON asset_components(tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_components_asset ON asset_components(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_components_branch ON asset_components(branch_id);
CREATE INDEX IF NOT EXISTS idx_asset_components_name ON asset_components(name);
CREATE INDEX IF NOT EXISTS idx_asset_components_ecosystem ON asset_components(ecosystem);
CREATE INDEX IF NOT EXISTS idx_asset_components_license ON asset_components(license);
CREATE INDEX IF NOT EXISTS idx_asset_components_purl ON asset_components(purl);
CREATE INDEX IF NOT EXISTS idx_asset_components_vuln_count ON asset_components(vulnerability_count DESC);
CREATE INDEX IF NOT EXISTS idx_asset_components_parent ON asset_components(parent_component_id);
CREATE INDEX IF NOT EXISTS idx_asset_components_risk ON asset_components(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_asset_components_tenant_asset ON asset_components(tenant_id, asset_id);

CREATE INDEX IF NOT EXISTS idx_licenses_spdx ON licenses(spdx_id);
CREATE INDEX IF NOT EXISTS idx_licenses_category ON licenses(category);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_asset_components_updated_at ON asset_components;
CREATE TRIGGER trigger_asset_components_updated_at
    BEFORE UPDATE ON asset_components
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
