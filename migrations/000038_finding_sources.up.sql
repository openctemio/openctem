-- =============================================================================
-- Migration 000038: Finding Sources (Seed Data)
-- OpenCTEM OSS Edition
-- =============================================================================
-- Defines standard finding source types for categorization.
-- =============================================================================

-- =============================================================================
-- Finding Source Categories
-- =============================================================================

CREATE TABLE IF NOT EXISTS finding_source_categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    color VARCHAR(20),
    display_order INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Finding Sources
-- =============================================================================

CREATE TABLE IF NOT EXISTS finding_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category_id UUID REFERENCES finding_source_categories(id) ON DELETE SET NULL,
    code VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    color VARCHAR(20),
    display_order INTEGER NOT NULL DEFAULT 0,
    is_system BOOLEAN NOT NULL DEFAULT TRUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_finding_sources_category ON finding_sources(category_id);
CREATE INDEX IF NOT EXISTS idx_finding_sources_code ON finding_sources(code);
CREATE INDEX IF NOT EXISTS idx_finding_sources_active ON finding_sources(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_finding_source_categories_code ON finding_source_categories(code);

-- =============================================================================
-- Seed Categories
-- =============================================================================

INSERT INTO finding_source_categories (code, name, description, icon, color, display_order) VALUES
('code_scanning', 'Code Scanning', 'Static and dynamic code analysis tools', 'code', 'blue', 1),
('dependency', 'Dependency', 'Software composition and dependency analysis', 'package', 'purple', 2),
('infrastructure', 'Infrastructure', 'Infrastructure and configuration scanning', 'server', 'orange', 3),
('runtime', 'Runtime', 'Runtime and dynamic testing', 'globe', 'green', 4),
('manual', 'Manual', 'Manual security assessments', 'shield', 'indigo', 5),
('import', 'Import', 'External data imports', 'upload', 'slate', 6)
ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    display_order = EXCLUDED.display_order,
    updated_at = NOW();

-- =============================================================================
-- Seed Finding Sources
-- =============================================================================

INSERT INTO finding_sources (code, name, description, icon, color, display_order, category_id) VALUES
('sast', 'SAST', 'Static Application Security Testing - source code analysis', 'code', 'blue', 1,
    (SELECT id FROM finding_source_categories WHERE code = 'code_scanning')),
('sca', 'SCA', 'Software Composition Analysis - dependency vulnerabilities', 'package', 'purple', 2,
    (SELECT id FROM finding_source_categories WHERE code = 'dependency')),
('dast', 'DAST', 'Dynamic Application Security Testing - runtime testing', 'globe', 'green', 3,
    (SELECT id FROM finding_source_categories WHERE code = 'runtime')),
('secret', 'Secrets', 'Hardcoded secrets and credentials', 'key', 'red', 4,
    (SELECT id FROM finding_source_categories WHERE code = 'code_scanning')),
('iac', 'IaC', 'Infrastructure as Code misconfiguration', 'server', 'orange', 5,
    (SELECT id FROM finding_source_categories WHERE code = 'infrastructure')),
('container', 'Container', 'Container image vulnerabilities', 'box', 'cyan', 6,
    (SELECT id FROM finding_source_categories WHERE code = 'infrastructure')),
('pentest', 'Penetration Test', 'Manual penetration testing findings', 'shield', 'indigo', 7,
    (SELECT id FROM finding_source_categories WHERE code = 'manual')),
('manual', 'Manual', 'Manually reported findings', 'edit', 'gray', 8,
    (SELECT id FROM finding_source_categories WHERE code = 'manual')),
('import', 'Import', 'Imported from external sources', 'upload', 'slate', 9,
    (SELECT id FROM finding_source_categories WHERE code = 'import')),
('sarif', 'SARIF', 'Imported from SARIF format', 'file-json', 'amber', 10,
    (SELECT id FROM finding_source_categories WHERE code = 'import'))
ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    display_order = EXCLUDED.display_order,
    category_id = EXCLUDED.category_id,
    updated_at = NOW();

-- =============================================================================
-- Triggers
-- =============================================================================

CREATE TRIGGER update_finding_sources_updated_at
    BEFORE UPDATE ON finding_sources
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_finding_source_categories_updated_at
    BEFORE UPDATE ON finding_source_categories
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE finding_source_categories IS 'Categories for grouping finding sources';
COMMENT ON TABLE finding_sources IS 'Standard finding source types for categorization';
COMMENT ON COLUMN finding_sources.code IS 'Unique code used in findings.source column';
COMMENT ON COLUMN finding_sources.is_system IS 'True if this is a built-in system source';
COMMENT ON COLUMN finding_sources.is_active IS 'Whether this source is active and can be used';
