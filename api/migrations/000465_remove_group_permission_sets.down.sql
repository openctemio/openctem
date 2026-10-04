-- Restore group permission sets and per-group permission overrides, with the
-- rows archived by the up migration. Rows whose tenant, group or role no
-- longer exists are skipped; a reference to a user who no longer exists is
-- restored as NULL (those columns are ON DELETE SET NULL).

CREATE TABLE IF NOT EXISTS permission_sets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
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

CREATE TABLE IF NOT EXISTS permission_set_items (
    permission_set_id UUID NOT NULL REFERENCES permission_sets(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL,
    modification_type VARCHAR(10) NOT NULL DEFAULT 'add',

    CONSTRAINT pk_permission_set_items PRIMARY KEY (permission_set_id, permission_id),
    CONSTRAINT chk_modification_type CHECK (modification_type IN ('add', 'remove'))
);

CREATE TABLE IF NOT EXISTS permission_set_versions (
    permission_set_id UUID NOT NULL REFERENCES permission_sets(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    changes JSONB NOT NULL DEFAULT '{}',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    changed_by UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT pk_permission_set_versions PRIMARY KEY (permission_set_id, version)
);

CREATE TABLE IF NOT EXISTS group_permission_sets (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    permission_set_id UUID NOT NULL REFERENCES permission_sets(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT pk_group_permission_sets PRIMARY KEY (group_id, permission_set_id)
);

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

CREATE INDEX IF NOT EXISTS idx_permission_sets_tenant ON permission_sets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_permission_sets_type ON permission_sets(set_type);
CREATE INDEX IF NOT EXISTS idx_permission_sets_parent ON permission_sets(parent_set_id) WHERE parent_set_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_permission_sets_active ON permission_sets(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_permission_sets_slug ON permission_sets(slug);
CREATE INDEX IF NOT EXISTS idx_permission_sets_system ON permission_sets(set_type) WHERE set_type = 'system';
CREATE INDEX IF NOT EXISTS idx_permission_set_items_set ON permission_set_items(permission_set_id);
CREATE INDEX IF NOT EXISTS idx_permission_set_items_perm ON permission_set_items(permission_id);
CREATE INDEX IF NOT EXISTS idx_permission_set_versions_set ON permission_set_versions(permission_set_id);
CREATE INDEX IF NOT EXISTS idx_group_permission_sets_group ON group_permission_sets(group_id);
CREATE INDEX IF NOT EXISTS idx_group_permission_sets_set ON group_permission_sets(permission_set_id);
CREATE INDEX IF NOT EXISTS idx_group_permissions_group ON group_permissions(group_id);
CREATE INDEX IF NOT EXISTS idx_group_permissions_perm ON group_permissions(permission_id);
CREATE INDEX IF NOT EXISTS idx_group_permissions_effect ON group_permissions(group_id, effect);

-- RLS policy in shadow mode, as migration 000158 created it.
DROP POLICY IF EXISTS permission_sets_tenant_isolation ON permission_sets;
CREATE POLICY permission_sets_tenant_isolation ON permission_sets
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

DO $$
BEGIN
    IF to_regclass('public.access_control_removed_archive') IS NULL THEN
        RETURN;
    END IF;

    -- Permission sets: parents are restored in a second pass so a set may
    -- reference a parent restored after it.
    INSERT INTO permission_sets (id, tenant_id, name, slug, description, set_type,
                                 parent_set_id, cloned_from_version, is_active, created_at, updated_at)
    SELECT r.id, r.tenant_id, r.name, r.slug, r.description, r.set_type,
           NULL, r.cloned_from_version, r.is_active, r.created_at, r.updated_at
    FROM access_control_removed_archive a,
         jsonb_populate_record(NULL::permission_sets, a.row_data) r
    WHERE a.source_table = 'permission_sets'
      AND (r.tenant_id IS NULL OR EXISTS (SELECT 1 FROM tenants t WHERE t.id = r.tenant_id))
    ON CONFLICT DO NOTHING;

    UPDATE permission_sets ps SET parent_set_id = r.parent_set_id
    FROM access_control_removed_archive a,
         jsonb_populate_record(NULL::permission_sets, a.row_data) r
    WHERE a.source_table = 'permission_sets' AND ps.id = r.id
      AND r.parent_set_id IS NOT NULL
      AND EXISTS (SELECT 1 FROM permission_sets p WHERE p.id = r.parent_set_id);

    INSERT INTO permission_set_items (permission_set_id, permission_id, modification_type)
    SELECT r.permission_set_id, r.permission_id, r.modification_type
    FROM access_control_removed_archive a,
         jsonb_populate_record(NULL::permission_set_items, a.row_data) r
    WHERE a.source_table = 'permission_set_items'
      AND EXISTS (SELECT 1 FROM permission_sets p WHERE p.id = r.permission_set_id)
    ON CONFLICT DO NOTHING;

    INSERT INTO permission_set_versions (permission_set_id, version, changes, changed_at, changed_by)
    SELECT r.permission_set_id, r.version, r.changes, r.changed_at,
           (SELECT u.id FROM users u WHERE u.id = r.changed_by)
    FROM access_control_removed_archive a,
         jsonb_populate_record(NULL::permission_set_versions, a.row_data) r
    WHERE a.source_table = 'permission_set_versions'
      AND EXISTS (SELECT 1 FROM permission_sets p WHERE p.id = r.permission_set_id)
    ON CONFLICT DO NOTHING;

    INSERT INTO group_permission_sets (group_id, permission_set_id, assigned_at, assigned_by)
    SELECT r.group_id, r.permission_set_id, r.assigned_at,
           (SELECT u.id FROM users u WHERE u.id = r.assigned_by)
    FROM access_control_removed_archive a,
         jsonb_populate_record(NULL::group_permission_sets, a.row_data) r
    WHERE a.source_table = 'group_permission_sets'
      AND EXISTS (SELECT 1 FROM groups g WHERE g.id = r.group_id)
      AND EXISTS (SELECT 1 FROM permission_sets p WHERE p.id = r.permission_set_id)
    ON CONFLICT DO NOTHING;

    INSERT INTO group_permissions (group_id, permission_id, effect, scope_type, scope_value, created_at, created_by)
    SELECT r.group_id, r.permission_id, r.effect, r.scope_type, r.scope_value, r.created_at,
           (SELECT u.id FROM users u WHERE u.id = r.created_by)
    FROM access_control_removed_archive a,
         jsonb_populate_record(NULL::group_permissions, a.row_data) r
    WHERE a.source_table = 'group_permissions'
      AND EXISTS (SELECT 1 FROM groups g WHERE g.id = r.group_id)
    ON CONFLICT DO NOTHING;

    INSERT INTO permissions
    SELECT r.*
    FROM access_control_removed_archive a,
         jsonb_populate_record(NULL::permissions, a.row_data) r
    WHERE a.source_table = 'permissions'
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO role_permissions
    SELECT r.*
    FROM access_control_removed_archive a,
         jsonb_populate_record(NULL::role_permissions, a.row_data) r
    WHERE a.source_table = 'role_permissions'
      AND EXISTS (SELECT 1 FROM roles ro WHERE ro.id = r.role_id)
      AND EXISTS (SELECT 1 FROM permissions p WHERE p.id = r.permission_id)
    ON CONFLICT DO NOTHING;

    DROP TABLE access_control_removed_archive;
END $$;
