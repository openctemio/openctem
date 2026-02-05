-- =============================================================================
-- Migration 015: Tools and Tool Categories
-- OpenCTEM OSS Edition
-- =============================================================================

-- Tool Categories
CREATE TABLE IF NOT EXISTS tool_categories (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    display_order INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

COMMENT ON TABLE tool_categories IS 'Categories for organizing security tools';

-- Tools (Scanner/tool definitions - can be global or tenant-specific)
CREATE TABLE IF NOT EXISTS tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(50) NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    logo_url VARCHAR(500),
    category_id VARCHAR(50) REFERENCES tool_categories(id) ON DELETE SET NULL,
    install_method VARCHAR(20),
    install_cmd TEXT,
    update_cmd TEXT,
    version_cmd VARCHAR(500),
    version_regex VARCHAR(200),
    current_version VARCHAR(50),
    latest_version VARCHAR(50),
    config_file_path VARCHAR(500),
    config_schema JSONB DEFAULT '{}',
    default_config JSONB DEFAULT '{}',
    capabilities TEXT[] DEFAULT '{}',
    supported_targets TEXT[] DEFAULT '{}',
    output_formats TEXT[] DEFAULT '{}',
    docs_url VARCHAR(500),
    github_url VARCHAR(500),
    is_active BOOLEAN DEFAULT TRUE,
    is_builtin BOOLEAN DEFAULT TRUE,
    tags TEXT[] DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_tools_install_method CHECK (install_method IS NULL OR install_method IN ('go', 'pip', 'docker', 'binary', 'npm', 'cargo', 'brew', 'apt')),
    CONSTRAINT tools_tenant_name_unique UNIQUE (tenant_id, name)
);

COMMENT ON TABLE tools IS 'Security tool registry (scanners, analyzers)';

-- Tenant Tool Configs (Per-tenant tool configuration overrides)
CREATE TABLE IF NOT EXISTS tenant_tool_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tool_id UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,

    -- Configuration override (merged with default_config)
    config JSONB NOT NULL DEFAULT '{}',

    -- Custom templates/patterns
    custom_templates JSONB DEFAULT '[]',    -- [{name, path, content}]
    custom_patterns JSONB DEFAULT '[]',     -- [{name, pattern}]
    custom_wordlists JSONB DEFAULT '[]',    -- [{name, path}]

    -- Status
    is_enabled BOOLEAN DEFAULT true,

    -- Audit
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT tenant_tool_configs_unique UNIQUE (tenant_id, tool_id)
);

COMMENT ON TABLE tenant_tool_configs IS 'Tenant-specific tool configuration overrides';

-- NOTE: tool_executions table is created in migration 000033_tool_executions.up.sql
-- because it references agents table which is created in 000016

-- =============================================================================
-- Indexes
-- =============================================================================

-- Tool categories indexes
CREATE INDEX IF NOT EXISTS idx_tool_categories_active ON tool_categories(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_tool_categories_order ON tool_categories(display_order);

-- Tools indexes
CREATE INDEX IF NOT EXISTS idx_tools_tenant ON tools(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tools_category ON tools(category_id);
CREATE INDEX IF NOT EXISTS idx_tools_is_active ON tools(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_tools_builtin ON tools(is_builtin) WHERE is_builtin = TRUE AND tenant_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_tools_created_by ON tools(created_by) WHERE created_by IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tools_capabilities ON tools USING GIN(capabilities);
CREATE INDEX IF NOT EXISTS idx_tools_supported_targets ON tools USING GIN(supported_targets);
CREATE INDEX IF NOT EXISTS idx_tools_tags ON tools USING GIN(tags);

-- Tenant tool configs indexes
CREATE INDEX IF NOT EXISTS idx_tenant_tool_configs_tenant ON tenant_tool_configs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_tool_configs_tool ON tenant_tool_configs(tool_id);
CREATE INDEX IF NOT EXISTS idx_tenant_tool_configs_enabled ON tenant_tool_configs(tenant_id, is_enabled) WHERE is_enabled = true;

-- Partial unique index for built-in tools (tenant_id IS NULL)
-- Required for ON CONFLICT when seeding built-in tools
CREATE UNIQUE INDEX IF NOT EXISTS idx_tools_builtin_name_unique ON tools(name) WHERE tenant_id IS NULL;

-- NOTE: tool_executions indexes are in migration 000033

-- =============================================================================
-- Seed Tool Categories
-- =============================================================================

INSERT INTO tool_categories (id, name, display_name, description, icon, display_order) VALUES
    ('sast', 'sast', 'SAST', 'Static Application Security Testing', 'Code', 1),
    ('sca', 'sca', 'SCA', 'Software Composition Analysis', 'Package', 2),
    ('dast', 'dast', 'DAST', 'Dynamic Application Security Testing', 'Globe', 3),
    ('secrets', 'secrets', 'Secret Detection', 'Credential and secret scanning', 'Key', 4),
    ('iac', 'iac', 'IaC Security', 'Infrastructure as Code scanning', 'Cloud', 5),
    ('container', 'container', 'Container Security', 'Container and image scanning', 'Box', 6),
    ('recon', 'recon', 'Reconnaissance', 'Asset discovery and enumeration', 'Search', 7),
    ('network', 'network', 'Network Security', 'Network vulnerability scanning', 'Network', 8)
ON CONFLICT (id) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    display_order = EXCLUDED.display_order;

-- =============================================================================
-- Seed Core Tools
-- =============================================================================

INSERT INTO tools (id, name, display_name, description, category_id, install_method, capabilities, supported_targets, output_formats, is_builtin) VALUES
    ('00000000-0000-0000-0000-000000000101', 'semgrep', 'Semgrep', 'Fast, lightweight static analysis for security', 'sast', 'pip', ARRAY['sast', 'security_analysis'], ARRAY['file', 'repository'], ARRAY['json', 'sarif'], TRUE),
    ('00000000-0000-0000-0000-000000000102', 'trivy', 'Trivy', 'Comprehensive vulnerability scanner', 'sca', 'binary', ARRAY['sca', 'container', 'iac'], ARRAY['file', 'repository', 'container'], ARRAY['json', 'sarif'], TRUE),
    ('00000000-0000-0000-0000-000000000103', 'gitleaks', 'Gitleaks', 'Secret detection in git repositories', 'secrets', 'go', ARRAY['secrets'], ARRAY['file', 'repository'], ARRAY['json', 'sarif'], TRUE),
    ('00000000-0000-0000-0000-000000000104', 'nuclei', 'Nuclei', 'Fast vulnerability scanner', 'dast', 'go', ARRAY['dast', 'recon'], ARRAY['url', 'domain', 'ip'], ARRAY['json', 'sarif'], TRUE),
    ('00000000-0000-0000-0000-000000000105', 'checkov', 'Checkov', 'Infrastructure as Code security scanner', 'iac', 'pip', ARRAY['iac', 'security_analysis'], ARRAY['file', 'repository'], ARRAY['json', 'sarif'], TRUE),
    ('00000000-0000-0000-0000-000000000106', 'grype', 'Grype', 'Vulnerability scanner for container images', 'sca', 'binary', ARRAY['sca', 'container'], ARRAY['container', 'file'], ARRAY['json', 'sarif'], TRUE),
    ('00000000-0000-0000-0000-000000000107', 'osv-scanner', 'OSV Scanner', 'Vulnerability scanner using OSV database', 'sca', 'go', ARRAY['sca'], ARRAY['file', 'repository'], ARRAY['json', 'sarif'], TRUE),
    ('00000000-0000-0000-0000-000000000108', 'trufflehog', 'TruffleHog', 'Secret and credential scanner', 'secrets', 'go', ARRAY['secrets'], ARRAY['file', 'repository'], ARRAY['json'], TRUE),
    ('00000000-0000-0000-0000-000000000109', 'kics', 'KICS', 'Infrastructure as Code scanner by Checkmarx', 'iac', 'docker', ARRAY['iac'], ARRAY['file', 'repository'], ARRAY['json', 'sarif'], TRUE),
    ('00000000-0000-0000-0000-000000000110', 'zap', 'OWASP ZAP', 'Web application security scanner', 'dast', 'docker', ARRAY['dast'], ARRAY['url'], ARRAY['json', 'sarif'], TRUE)
ON CONFLICT (name) WHERE tenant_id IS NULL DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    category_id = EXCLUDED.category_id,
    install_method = EXCLUDED.install_method,
    capabilities = EXCLUDED.capabilities,
    supported_targets = EXCLUDED.supported_targets,
    output_formats = EXCLUDED.output_formats;

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_tool_categories_updated_at ON tool_categories;
CREATE TRIGGER trigger_tool_categories_updated_at
    BEFORE UPDATE ON tool_categories
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_tools_updated_at ON tools;
CREATE TRIGGER trigger_tools_updated_at
    BEFORE UPDATE ON tools
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_tenant_tool_configs_updated_at ON tenant_tool_configs;
CREATE TRIGGER trigger_tenant_tool_configs_updated_at
    BEFORE UPDATE ON tenant_tool_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
