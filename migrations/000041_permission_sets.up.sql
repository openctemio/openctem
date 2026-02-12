-- =============================================================================
-- Migration 041: Permission Sets
-- OpenCTEM OSS Edition
-- =============================================================================
-- Flexible permission management with inheritance and versioning.
-- Supports system templates, extended sets, cloned sets, and custom sets.
-- =============================================================================

-- =============================================================================
-- Permission Sets
-- =============================================================================

CREATE TABLE IF NOT EXISTS permission_sets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL = system template
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    description TEXT,
    set_type VARCHAR(20) NOT NULL DEFAULT 'custom',
    parent_set_id UUID REFERENCES permission_sets(id) ON DELETE SET NULL,
    cloned_from_version INTEGER,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_permission_set_type CHECK (set_type IN ('system', 'extended', 'cloned', 'custom')),
    CONSTRAINT uq_permission_sets_slug UNIQUE (tenant_id, slug)
);

COMMENT ON TABLE permission_sets IS 'Permission set definitions with inheritance support';
COMMENT ON COLUMN permission_sets.tenant_id IS 'NULL for system-wide templates, set for tenant-specific sets';
COMMENT ON COLUMN permission_sets.set_type IS 'system=platform template, extended=inherits parent, cloned=independent copy, custom=from scratch';

-- =============================================================================
-- Permission Set Items
-- =============================================================================

CREATE TABLE IF NOT EXISTS permission_set_items (
    permission_set_id UUID NOT NULL REFERENCES permission_sets(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL,
    modification_type VARCHAR(10) NOT NULL DEFAULT 'add',

    CONSTRAINT pk_permission_set_items PRIMARY KEY (permission_set_id, permission_id),
    CONSTRAINT chk_modification_type CHECK (modification_type IN ('add', 'remove'))
);

COMMENT ON TABLE permission_set_items IS 'Individual permission entries within a permission set';
COMMENT ON COLUMN permission_set_items.modification_type IS 'add=grant permission, remove=revoke (for extended sets overriding parent)';

-- =============================================================================
-- Permission Set Versions
-- =============================================================================

CREATE TABLE IF NOT EXISTS permission_set_versions (
    permission_set_id UUID NOT NULL REFERENCES permission_sets(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    changes JSONB NOT NULL DEFAULT '{}',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT pk_permission_set_versions PRIMARY KEY (permission_set_id, version)
);

COMMENT ON TABLE permission_set_versions IS 'Version history for permission set changes';
COMMENT ON COLUMN permission_set_versions.changes IS 'JSON with added[], removed[], initial bool';

-- =============================================================================
-- Group Permission Sets (link table)
-- =============================================================================

CREATE TABLE IF NOT EXISTS group_permission_sets (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    permission_set_id UUID NOT NULL REFERENCES permission_sets(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT pk_group_permission_sets PRIMARY KEY (group_id, permission_set_id)
);

COMMENT ON TABLE group_permission_sets IS 'Maps permission sets to groups';

-- =============================================================================
-- User Accessible Assets (materialized view as table)
-- =============================================================================

CREATE TABLE IF NOT EXISTS user_accessible_assets (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ownership_type VARCHAR(20) NOT NULL DEFAULT 'primary',

    CONSTRAINT chk_ownership_type CHECK (ownership_type IN ('primary', 'secondary', 'stakeholder', 'informed'))
);

COMMENT ON TABLE user_accessible_assets IS 'Denormalized view of which assets a user can access through group membership';

-- Function to refresh user_accessible_assets
CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    WHERE gm.is_active = TRUE;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Indexes
-- =============================================================================

-- Permission Sets
CREATE INDEX IF NOT EXISTS idx_permission_sets_tenant ON permission_sets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_permission_sets_type ON permission_sets(set_type);
CREATE INDEX IF NOT EXISTS idx_permission_sets_parent ON permission_sets(parent_set_id) WHERE parent_set_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_permission_sets_active ON permission_sets(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_permission_sets_slug ON permission_sets(slug);
CREATE INDEX IF NOT EXISTS idx_permission_sets_system ON permission_sets(set_type) WHERE set_type = 'system';

-- Permission Set Items
CREATE INDEX IF NOT EXISTS idx_permission_set_items_set ON permission_set_items(permission_set_id);
CREATE INDEX IF NOT EXISTS idx_permission_set_items_perm ON permission_set_items(permission_id);

-- Permission Set Versions
CREATE INDEX IF NOT EXISTS idx_permission_set_versions_set ON permission_set_versions(permission_set_id);

-- Group Permission Sets
CREATE INDEX IF NOT EXISTS idx_group_permission_sets_group ON group_permission_sets(group_id);
CREATE INDEX IF NOT EXISTS idx_group_permission_sets_set ON group_permission_sets(permission_set_id);

-- User Accessible Assets
CREATE INDEX IF NOT EXISTS idx_user_accessible_assets_user ON user_accessible_assets(user_id);
CREATE INDEX IF NOT EXISTS idx_user_accessible_assets_tenant ON user_accessible_assets(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_user_accessible_assets_asset ON user_accessible_assets(asset_id);
CREATE INDEX IF NOT EXISTS idx_user_accessible_assets_lookup ON user_accessible_assets(user_id, asset_id);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_permission_sets_updated_at ON permission_sets;
CREATE TRIGGER trigger_permission_sets_updated_at
    BEFORE UPDATE ON permission_sets
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
