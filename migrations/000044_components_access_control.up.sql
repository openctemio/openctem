-- =============================================================================
-- Migration 044: Global Components, Component Licenses, Access Control
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds:
-- 1. Global components table (PURL-based deduplication)
-- 2. Component-license junction table
-- 3. Group-level permission overrides
-- 4. Assignment rules for automated group assignment
-- 5. Schema fixes for licenses and asset_components constraints
-- =============================================================================

-- =============================================================================
-- Schema Fixes
-- =============================================================================

-- Add UNIQUE constraint on licenses.spdx_id (required for ON CONFLICT in component_repository)
DO $$ BEGIN
    ALTER TABLE licenses ADD CONSTRAINT uq_licenses_spdx_id UNIQUE (spdx_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Add UNIQUE index on asset_components(asset_id, component_id, path)
-- (used by component_repository ON CONFLICT)
CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_components_asset_component_path
    ON asset_components (asset_id, component_id, path);

-- =============================================================================
-- Global Components Table
-- =============================================================================

CREATE TABLE IF NOT EXISTS components (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purl VARCHAR(500) NOT NULL,
    name VARCHAR(255) NOT NULL,
    version VARCHAR(100),
    ecosystem VARCHAR(50) NOT NULL,
    description TEXT,
    homepage VARCHAR(500),
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_components_purl UNIQUE (purl),
    CONSTRAINT chk_components_ecosystem CHECK (ecosystem IN (
        'npm', 'maven', 'pypi', 'go', 'cargo', 'nuget', 'rubygems',
        'composer', 'cocoapods', 'hex', 'pub', 'swiftpm', 'cran',
        'gradle', 'sbt', 'packagist', 'homebrew', 'other'
    ))
);

COMMENT ON TABLE components IS 'Global component registry with PURL-based deduplication';
COMMENT ON COLUMN components.purl IS 'Package URL (RFC) - unique identifier for the component';

-- Update findings.component_id to reference components instead of asset_components
-- Drop old FK if it exists, add new one
DO $$ BEGIN
    ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_component_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD CONSTRAINT findings_component_id_fkey
        FOREIGN KEY (component_id) REFERENCES components(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- =============================================================================
-- Component Licenses (junction table)
-- =============================================================================

CREATE TABLE IF NOT EXISTS component_licenses (
    component_id UUID NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    license_id VARCHAR(100) NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,

    CONSTRAINT pk_component_licenses PRIMARY KEY (component_id, license_id)
);

COMMENT ON TABLE component_licenses IS 'Links global components to their licenses';

-- =============================================================================
-- Group Permissions (per-group permission overrides)
-- =============================================================================

CREATE TABLE IF NOT EXISTS group_permissions (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL,
    effect VARCHAR(10) NOT NULL DEFAULT 'allow',
    scope_type VARCHAR(50),
    scope_value JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT pk_group_permissions PRIMARY KEY (group_id, permission_id),
    CONSTRAINT chk_permission_effect CHECK (effect IN ('allow', 'deny'))
);

COMMENT ON TABLE group_permissions IS 'Per-group permission overrides with optional scope filtering';
COMMENT ON COLUMN group_permissions.effect IS 'allow=grant, deny=revoke permission';
COMMENT ON COLUMN group_permissions.scope_type IS 'Optional scope type for scoped permissions';
COMMENT ON COLUMN group_permissions.scope_value IS 'Optional scope value (JSON) for scoped permissions';

-- =============================================================================
-- Assignment Rules
-- =============================================================================

CREATE TABLE IF NOT EXISTS assignment_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    priority INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    conditions JSONB NOT NULL DEFAULT '[]',
    target_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    options JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL
);

COMMENT ON TABLE assignment_rules IS 'Rules for automated asset/finding assignment to groups';
COMMENT ON COLUMN assignment_rules.priority IS 'Higher priority rules are evaluated first';
COMMENT ON COLUMN assignment_rules.conditions IS 'JSON array of conditions to match';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Components
CREATE INDEX IF NOT EXISTS idx_components_purl ON components(purl);
CREATE INDEX IF NOT EXISTS idx_components_name ON components(name);
CREATE INDEX IF NOT EXISTS idx_components_ecosystem ON components(ecosystem);
CREATE INDEX IF NOT EXISTS idx_components_vuln_count ON components(vulnerability_count DESC);

-- Component Licenses
CREATE INDEX IF NOT EXISTS idx_component_licenses_component ON component_licenses(component_id);
CREATE INDEX IF NOT EXISTS idx_component_licenses_license ON component_licenses(license_id);

-- Group Permissions
CREATE INDEX IF NOT EXISTS idx_group_permissions_group ON group_permissions(group_id);
CREATE INDEX IF NOT EXISTS idx_group_permissions_perm ON group_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_group_permissions_effect ON group_permissions(group_id, effect);

-- Assignment Rules
CREATE INDEX IF NOT EXISTS idx_assignment_rules_tenant ON assignment_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_assignment_rules_active ON assignment_rules(tenant_id, is_active)
    WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_assignment_rules_priority ON assignment_rules(tenant_id, priority DESC);
CREATE INDEX IF NOT EXISTS idx_assignment_rules_target ON assignment_rules(target_group_id);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_components_updated_at ON components;
CREATE TRIGGER trigger_components_updated_at
    BEFORE UPDATE ON components
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_assignment_rules_updated_at ON assignment_rules;
CREATE TRIGGER trigger_assignment_rules_updated_at
    BEFORE UPDATE ON assignment_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
