-- =============================================================================
-- Migration 031: Target Asset Type Mappings (Smart Filtering)
-- OpenCTEM OSS Edition
-- =============================================================================
-- Maps tool target types (e.g., url, domain, ip) to asset types
-- Used for smart filtering at scan trigger time.

CREATE TABLE IF NOT EXISTS target_asset_type_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The tool's target type (from tool.supported_targets)
    target_type VARCHAR(50) NOT NULL,

    -- The asset type this target maps to (from assets.asset_type)
    asset_type VARCHAR(50) NOT NULL,

    -- Priority for ordering (lower = higher priority)
    priority INTEGER NOT NULL DEFAULT 100,

    -- Description
    description TEXT,

    -- Whether this mapping is active
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,

    CONSTRAINT uq_target_asset_type UNIQUE (target_type, asset_type)
);

COMMENT ON TABLE target_asset_type_mappings IS 'Maps tool target types to asset types for smart filtering at scan trigger';
COMMENT ON COLUMN target_asset_type_mappings.target_type IS 'The target type from tool.supported_targets (e.g., url, domain, ip, repository)';
COMMENT ON COLUMN target_asset_type_mappings.asset_type IS 'The asset type from assets.asset_type that this target can scan';
COMMENT ON COLUMN target_asset_type_mappings.priority IS 'Lower values = higher priority. Used when ordering compatible types.';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_target_mappings_target_type ON target_asset_type_mappings(target_type)
    WHERE is_active = TRUE;

CREATE INDEX IF NOT EXISTS idx_target_mappings_asset_type ON target_asset_type_mappings(asset_type)
    WHERE is_active = TRUE;

-- =============================================================================
-- Seed Data: Default Mappings
-- =============================================================================

-- URL targets -> web-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('url', 'website', 10),
    ('url', 'web_application', 20),
    ('url', 'api', 30),
    ('url', 'http_service', 40),
    ('url', 'discovered_url', 50)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Domain targets -> domain-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('domain', 'domain', 10),
    ('domain', 'subdomain', 20)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- IP targets -> IP and network-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('ip', 'ip_address', 10),
    ('ip', 'host', 20),
    ('ip', 'server', 30)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Host targets -> host-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('host', 'host', 10),
    ('host', 'server', 20),
    ('host', 'ip_address', 30),
    ('host', 'compute', 40)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Repository/file targets -> code-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('repository', 'repository', 10),
    ('file', 'repository', 10)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Container targets -> container-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('container', 'container', 10),
    ('container', 'container_registry', 20)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Kubernetes targets -> k8s-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('kubernetes', 'kubernetes_cluster', 10),
    ('kubernetes', 'kubernetes_namespace', 20)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Cloud targets -> cloud-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('cloud', 'cloud_account', 10),
    ('cloud', 'compute', 20),
    ('cloud', 'storage', 30),
    ('cloud', 'serverless', 40),
    ('cloud', 's3_bucket', 50),
    ('cloud', 'vpc', 60)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Network targets -> network-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('network', 'network', 10),
    ('network', 'subnet', 20),
    ('network', 'vpc', 30),
    ('network', 'firewall', 40),
    ('network', 'load_balancer', 50)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Service targets -> service-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('service', 'service', 10),
    ('service', 'open_port', 20),
    ('service', 'http_service', 30)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Port targets -> port/service asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('port', 'open_port', 10),
    ('port', 'service', 20)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Database targets -> data-related asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('database', 'database', 10),
    ('database', 'data_store', 20)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Mobile targets -> mobile app asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('mobile', 'mobile_app', 10)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- API targets -> API asset types
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('api', 'api', 10)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- Certificate targets
INSERT INTO target_asset_type_mappings (target_type, asset_type, priority) VALUES
    ('certificate', 'certificate', 10)
ON CONFLICT (target_type, asset_type) DO NOTHING;

-- =============================================================================
-- Helper Functions
-- =============================================================================

-- Function to check if a tool can scan an asset type
CREATE OR REPLACE FUNCTION can_tool_scan_asset_type(
    p_target_types TEXT[],
    p_asset_type TEXT
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM target_asset_type_mappings
        WHERE target_type = ANY(p_target_types)
          AND asset_type = p_asset_type
          AND is_active = TRUE
    );
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION can_tool_scan_asset_type(TEXT[], TEXT) IS 'Returns TRUE if any of the given target types can scan the specified asset type';

-- Function to get all compatible asset types for given target types
CREATE OR REPLACE FUNCTION get_compatible_asset_types(
    p_target_types TEXT[]
) RETURNS TABLE(asset_type TEXT) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT m.asset_type::TEXT
    FROM target_asset_type_mappings m
    WHERE m.target_type = ANY(p_target_types)
      AND m.is_active = TRUE
    ORDER BY m.asset_type;
END;
$$ LANGUAGE plpgsql STABLE;

COMMENT ON FUNCTION get_compatible_asset_types(TEXT[]) IS 'Returns all asset types that can be scanned by any of the given target types';

