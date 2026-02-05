-- =============================================================================
-- Migration 030: Capabilities Registry
-- OpenCTEM OSS Edition
-- =============================================================================
-- Normalized table for tool capabilities with metadata for UI display.
-- Supports both platform (builtin) capabilities and tenant custom capabilities.

CREATE TABLE IF NOT EXISTS capabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Tenant scoping (NULL = platform/builtin capability)
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,

    -- Identity
    name VARCHAR(50) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,

    -- UI customization
    icon VARCHAR(50) DEFAULT 'zap',
    color VARCHAR(20) DEFAULT 'gray',

    -- Classification
    category VARCHAR(50),

    -- Status
    is_builtin BOOLEAN NOT NULL DEFAULT false,
    sort_order INTEGER DEFAULT 0,

    -- Audit
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Unique name per scope (platform or tenant)
    UNIQUE NULLS NOT DISTINCT (tenant_id, name)
);

COMMENT ON TABLE capabilities IS 'Capability registry - both platform (builtin) and tenant custom capabilities';
COMMENT ON COLUMN capabilities.tenant_id IS 'NULL for platform capabilities, UUID for tenant custom capabilities';
COMMENT ON COLUMN capabilities.name IS 'Unique slug identifier within scope';
COMMENT ON COLUMN capabilities.icon IS 'Lucide icon name for UI display';
COMMENT ON COLUMN capabilities.color IS 'Badge color for UI display';
COMMENT ON COLUMN capabilities.category IS 'Grouping category: security, recon, analysis';

-- Junction table for tool-capability many-to-many relationship
CREATE TABLE IF NOT EXISTS tool_capabilities (
    tool_id UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    capability_id UUID NOT NULL REFERENCES capabilities(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tool_id, capability_id)
);

COMMENT ON TABLE tool_capabilities IS 'Junction table linking tools to their capabilities';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_capabilities_tenant ON capabilities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_capabilities_builtin ON capabilities(is_builtin) WHERE is_builtin = true;
CREATE INDEX IF NOT EXISTS idx_capabilities_category ON capabilities(category);
CREATE INDEX IF NOT EXISTS idx_capabilities_sort ON capabilities(sort_order);

-- Index for reverse lookups (find tools by capability)
CREATE INDEX IF NOT EXISTS idx_tool_capabilities_capability ON tool_capabilities(capability_id);

-- =============================================================================
-- Seed Data: Builtin (Platform) Capabilities
-- =============================================================================

INSERT INTO capabilities (tenant_id, name, display_name, description, icon, color, category, is_builtin, sort_order) VALUES
    -- Security Analysis (Primary scanning capabilities)
    (NULL, 'sast', 'SAST', 'Static Application Security Testing - analyze source code', 'code', 'blue', 'security', true, 1),
    (NULL, 'sca', 'SCA', 'Software Composition Analysis - scan dependencies', 'package', 'purple', 'security', true, 2),
    (NULL, 'dast', 'DAST', 'Dynamic Application Security Testing - test running apps', 'globe', 'green', 'security', true, 3),
    (NULL, 'secrets', 'Secrets', 'Secret Detection - find hardcoded credentials', 'key', 'red', 'security', true, 4),
    (NULL, 'iac', 'IaC', 'Infrastructure as Code security scanning', 'server', 'orange', 'security', true, 5),
    (NULL, 'container', 'Container', 'Container and image security scanning', 'box', 'cyan', 'security', true, 6),

    -- Specialized Security (Sub-capabilities)
    (NULL, 'web', 'Web Security', 'Web application vulnerability scanning', 'globe-2', 'green', 'security', true, 10),
    (NULL, 'xss', 'XSS', 'Cross-Site Scripting detection', 'alert-triangle', 'amber', 'security', true, 11),
    (NULL, 'terraform', 'Terraform', 'Terraform-specific security checks', 'file-code', 'violet', 'security', true, 12),
    (NULL, 'docker', 'Docker', 'Docker-specific security scanning', 'container', 'sky', 'security', true, 13),

    -- Reconnaissance
    (NULL, 'recon', 'Recon', 'General reconnaissance and discovery', 'search', 'yellow', 'recon', true, 20),
    (NULL, 'subdomain', 'Subdomain', 'Subdomain enumeration and discovery', 'layers', 'lime', 'recon', true, 21),
    (NULL, 'http', 'HTTP', 'HTTP probing and analysis', 'wifi', 'teal', 'recon', true, 22),
    (NULL, 'portscan', 'Port Scan', 'TCP/UDP port scanning', 'radio', 'indigo', 'recon', true, 23),
    (NULL, 'crawler', 'Crawler', 'Web crawling and spidering', 'spider', 'fuchsia', 'recon', true, 24),

    -- Analysis & Reporting
    (NULL, 'sbom', 'SBOM', 'Software Bill of Materials generation', 'file-text', 'slate', 'analysis', true, 30)

ON CONFLICT (tenant_id, name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    category = EXCLUDED.category,
    sort_order = EXCLUDED.sort_order,
    updated_at = NOW();

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_capabilities_updated_at ON capabilities;
CREATE TRIGGER trigger_capabilities_updated_at
    BEFORE UPDATE ON capabilities
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

