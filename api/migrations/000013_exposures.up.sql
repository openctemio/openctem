-- =============================================================================
-- Migration 013: Exposures and Attack Paths
-- OpenCTEM OSS Edition
-- =============================================================================

-- Exposures (Assets exposed to attack surface)
CREATE TABLE IF NOT EXISTS exposures (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    cvss_score DECIMAL(3,1),
    cve_id VARCHAR(20),
    source VARCHAR(100),
    source_id VARCHAR(255),
    remediation TEXT,
    due_date TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_exposures_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'none')),
    CONSTRAINT chk_exposures_status CHECK (status IN ('open', 'in_progress', 'resolved', 'accepted', 'false_positive'))
);

COMMENT ON TABLE exposures IS 'Security exposures discovered on assets';

-- Attack Paths (Attack chain modeling)
CREATE TABLE IF NOT EXISTS attack_paths (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    risk_score INTEGER DEFAULT 0,
    complexity VARCHAR(20),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_attack_paths_complexity CHECK (complexity IS NULL OR complexity IN ('low', 'medium', 'high')),
    CONSTRAINT chk_attack_paths_status CHECK (status IN ('active', 'mitigated', 'archived')),
    CONSTRAINT chk_attack_paths_risk_score CHECK (risk_score >= 0 AND risk_score <= 100)
);

COMMENT ON TABLE attack_paths IS 'Attack chain modeling for threat visualization';

-- Attack Path Nodes
CREATE TABLE IF NOT EXISTS attack_path_nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_path_id UUID NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    exposure_id UUID REFERENCES exposures(id) ON DELETE SET NULL,
    node_order INTEGER NOT NULL,
    node_type VARCHAR(50) NOT NULL,
    action VARCHAR(100),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_attack_path_nodes_type CHECK (node_type IN ('entry', 'pivot', 'target', 'lateral_movement', 'privilege_escalation'))
);

COMMENT ON TABLE attack_path_nodes IS 'Individual nodes within an attack path';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Exposures indexes
CREATE INDEX IF NOT EXISTS idx_exposures_tenant_id ON exposures(tenant_id);
CREATE INDEX IF NOT EXISTS idx_exposures_asset_id ON exposures(asset_id);
CREATE INDEX IF NOT EXISTS idx_exposures_category ON exposures(category);
CREATE INDEX IF NOT EXISTS idx_exposures_severity ON exposures(severity);
CREATE INDEX IF NOT EXISTS idx_exposures_status ON exposures(status);
CREATE INDEX IF NOT EXISTS idx_exposures_cve_id ON exposures(cve_id) WHERE cve_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exposures_source ON exposures(source);
CREATE INDEX IF NOT EXISTS idx_exposures_created_at ON exposures(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_exposures_tenant_status ON exposures(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_exposures_tenant_severity ON exposures(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_exposures_metadata ON exposures USING GIN(metadata);

-- Attack paths indexes
CREATE INDEX IF NOT EXISTS idx_attack_paths_tenant_id ON attack_paths(tenant_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_status ON attack_paths(status);
CREATE INDEX IF NOT EXISTS idx_attack_paths_risk_score ON attack_paths(risk_score DESC);

-- Attack path nodes indexes
CREATE INDEX IF NOT EXISTS idx_attack_path_nodes_path_id ON attack_path_nodes(attack_path_id);
CREATE INDEX IF NOT EXISTS idx_attack_path_nodes_asset_id ON attack_path_nodes(asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_attack_path_nodes_exposure_id ON attack_path_nodes(exposure_id) WHERE exposure_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_attack_path_nodes_order ON attack_path_nodes(attack_path_id, node_order);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_exposures_updated_at ON exposures;
CREATE TRIGGER trigger_exposures_updated_at
    BEFORE UPDATE ON exposures
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_attack_paths_updated_at ON attack_paths;
CREATE TRIGGER trigger_attack_paths_updated_at
    BEFORE UPDATE ON attack_paths
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
