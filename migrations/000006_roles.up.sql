-- =============================================================================
-- Migration 006: Roles and RBAC
-- OpenCTEM OSS Edition
-- =============================================================================

-- Roles (Permission bundles)
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    slug VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    hierarchy_level INT NOT NULL DEFAULT 50,
    has_full_data_access BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT roles_slug_unique UNIQUE NULLS NOT DISTINCT (tenant_id, slug)
);

COMMENT ON TABLE roles IS 'Roles define what actions users can perform (permissions)';
COMMENT ON COLUMN roles.tenant_id IS 'NULL for system roles, tenant UUID for custom roles';
COMMENT ON COLUMN roles.is_system IS 'System roles cannot be modified or deleted';
COMMENT ON COLUMN roles.hierarchy_level IS 'Higher level = more privileges (owner=100, admin=80, member=50, viewer=20)';
COMMENT ON COLUMN roles.has_full_data_access IS 'If true, user sees all data regardless of group membership';

-- Role Permissions (FK to permissions)
CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT role_permissions_unique UNIQUE (role_id, permission_id)
);

COMMENT ON TABLE role_permissions IS 'Maps roles to their permissions';

-- User Roles (Multiple roles per user)
CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,

    CONSTRAINT user_roles_unique UNIQUE (user_id, tenant_id, role_id)
);

COMMENT ON TABLE user_roles IS 'Maps users to their roles (multiple roles per user supported)';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_roles_system ON roles(is_system) WHERE is_system = TRUE;
CREATE INDEX IF NOT EXISTS idx_roles_slug ON roles(slug);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_tenant ON user_roles(user_id, tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_tenant ON user_roles(tenant_id);

-- =============================================================================
-- Seed System Roles
-- =============================================================================

INSERT INTO roles (id, tenant_id, slug, name, description, is_system, hierarchy_level, has_full_data_access)
VALUES
    ('00000000-0000-0000-0000-000000000001', NULL, 'owner', 'Owner',
     'Full access to everything including team management', TRUE, 100, TRUE),
    ('00000000-0000-0000-0000-000000000002', NULL, 'admin', 'Administrator',
     'Administrative access to most resources', TRUE, 80, TRUE),
    ('00000000-0000-0000-0000-000000000003', NULL, 'member', 'Member',
     'Standard member with read/write access to assigned resources', TRUE, 50, FALSE),
    ('00000000-0000-0000-0000-000000000004', NULL, 'viewer', 'Viewer',
     'Read-only access to assigned resources', TRUE, 20, FALSE)
ON CONFLICT DO NOTHING;

-- Owner: ALL permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id FROM permissions
ON CONFLICT DO NOTHING;

-- Admin: all except team:delete
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002', id
FROM permissions
WHERE id NOT IN ('team:delete')
ON CONFLICT DO NOTHING;

-- Member: read/write, no delete, no admin features
-- Permission IDs use hierarchical format matching Go/frontend constants
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003', id
FROM permissions
WHERE id IN (
    -- Core
    'dashboard:read',
    'audit:read',
    'settings:read',
    -- Assets
    'assets:read', 'assets:write',
    'assets:groups:read', 'assets:groups:write',
    'assets:components:read', 'assets:components:write',
    -- Findings
    'findings:read', 'findings:write', 'findings:status', 'findings:triage',
    'findings:vulnerabilities:read',
    'findings:credentials:read',
    'findings:exposures:read', 'findings:exposures:write',
    'findings:remediation:read', 'findings:remediation:write',
    'findings:workflows:read',
    'findings:suppressions:read',
    'findings:policies:read',
    -- Scans
    'scans:read', 'scans:write', 'scans:execute',
    'scans:profiles:read', 'scans:profiles:write',
    'scans:sources:read', 'scans:sources:write',
    'scans:tools:read',
    'scans:tenant_tools:read', 'scans:tenant_tools:write',
    'scans:templates:read', 'scans:templates:write',
    'scans:secret_store:read', 'scans:secret_store:write',
    -- Agents
    'agents:read', 'agents:write',
    'agents:commands:read', 'agents:commands:write',
    -- Team (read-only for members)
    'team:read',
    'team:members:read',
    'team:groups:read',
    'team:roles:read',
    'team:permission_sets:read',
    -- Integrations (read-only)
    'integrations:read',
    'integrations:scm:read', 'integrations:scm:write',
    'integrations:notifications:read',
    'integrations:webhooks:read',
    'integrations:api_keys:read',
    'integrations:pipelines:read', 'integrations:pipelines:write',
    -- Settings
    'settings:sla:read',
    'settings:billing:read',
    -- Attack Surface
    'attack_surface:scope:read', 'attack_surface:scope:write',
    -- Validation
    'validation:read', 'validation:write',
    -- Reports
    'reports:read', 'reports:write',
    -- Threat Intel
    'threat_intel:read',
    -- AI Triage
    'ai_triage:read', 'ai_triage:trigger'
)
ON CONFLICT DO NOTHING;

-- Viewer: read only
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000004', id
FROM permissions
WHERE id LIKE '%:read'
ON CONFLICT DO NOTHING;

-- =============================================================================
-- Helper Functions
-- =============================================================================

-- Get user permissions
CREATE OR REPLACE FUNCTION get_user_permissions(p_tenant_id UUID, p_user_id UUID)
RETURNS TABLE(permission_id VARCHAR(100)) AS $$
BEGIN
    RETURN QUERY
    SELECT DISTINCT rp.permission_id
    FROM user_roles ur
    JOIN role_permissions rp ON rp.role_id = ur.role_id
    WHERE ur.tenant_id = p_tenant_id
      AND ur.user_id = p_user_id;
END;
$$ LANGUAGE plpgsql;

-- Check if user has permission
CREATE OR REPLACE FUNCTION user_has_permission(p_tenant_id UUID, p_user_id UUID, p_permission VARCHAR(100))
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        WHERE ur.tenant_id = p_tenant_id
          AND ur.user_id = p_user_id
          AND rp.permission_id = p_permission
    );
END;
$$ LANGUAGE plpgsql;

-- Check if user has full data access
CREATE OR REPLACE FUNCTION user_has_full_data_access(p_tenant_id UUID, p_user_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE ur.tenant_id = p_tenant_id
          AND ur.user_id = p_user_id
          AND r.has_full_data_access = TRUE
    );
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_roles_updated_at ON roles;
CREATE TRIGGER trigger_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- View: User Effective Role
-- =============================================================================
-- Returns the highest-priority role for each user in each tenant

CREATE OR REPLACE VIEW v_user_effective_role AS
SELECT DISTINCT ON (ur.user_id, ur.tenant_id)
    ur.user_id,
    ur.tenant_id,
    r.slug AS role,
    r.name AS role_name,
    r.hierarchy_level,
    r.has_full_data_access
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
ORDER BY ur.user_id, ur.tenant_id, r.hierarchy_level DESC;

COMMENT ON VIEW v_user_effective_role IS
    'Returns the highest-priority role for each user in each tenant';

-- =============================================================================
-- Sync Functions: tenant_members -> user_roles
-- =============================================================================

CREATE OR REPLACE FUNCTION sync_tenant_member_to_user_roles()
RETURNS TRIGGER AS $$
DECLARE
    v_role_id UUID;
BEGIN
    -- Get the system role ID based on role slug
    SELECT id INTO v_role_id
    FROM roles
    WHERE slug = NEW.role
      AND is_system = TRUE
      AND tenant_id IS NULL;

    IF v_role_id IS NULL THEN
        -- If role not found, log warning but don't fail
        RAISE WARNING 'Role % not found in roles table, skipping user_roles sync', NEW.role;
        RETURN NEW;
    END IF;

    IF TG_OP = 'INSERT' THEN
        -- Insert into user_roles if not exists
        INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at, assigned_by)
        VALUES (NEW.user_id, NEW.tenant_id, v_role_id, NEW.joined_at, NEW.invited_by)
        ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING;

    ELSIF TG_OP = 'UPDATE' THEN
        -- If role changed, remove old role and add new one
        IF OLD.role != NEW.role THEN
            -- Get old role ID
            DECLARE
                v_old_role_id UUID;
            BEGIN
                SELECT id INTO v_old_role_id
                FROM roles
                WHERE slug = OLD.role
                  AND is_system = TRUE
                  AND tenant_id IS NULL;

                -- Remove old role
                IF v_old_role_id IS NOT NULL THEN
                    DELETE FROM user_roles
                    WHERE user_id = NEW.user_id
                      AND tenant_id = NEW.tenant_id
                      AND role_id = v_old_role_id;
                END IF;

                -- Add new role
                INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at)
                VALUES (NEW.user_id, NEW.tenant_id, v_role_id, NOW())
                ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING;
            END;
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION sync_tenant_member_delete_to_user_roles()
RETURNS TRIGGER AS $$
BEGIN
    -- When a tenant_member is deleted, remove all their roles in that tenant
    DELETE FROM user_roles
    WHERE user_id = OLD.user_id
      AND tenant_id = OLD.tenant_id;

    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- Create triggers on tenant_members to sync to user_roles
DROP TRIGGER IF EXISTS trigger_sync_tenant_member_to_user_roles ON tenant_members;
CREATE TRIGGER trigger_sync_tenant_member_to_user_roles
    AFTER INSERT OR UPDATE ON tenant_members
    FOR EACH ROW
    EXECUTE FUNCTION sync_tenant_member_to_user_roles();

DROP TRIGGER IF EXISTS trigger_sync_tenant_member_delete ON tenant_members;
CREATE TRIGGER trigger_sync_tenant_member_delete
    AFTER DELETE ON tenant_members
    FOR EACH ROW
    EXECUTE FUNCTION sync_tenant_member_delete_to_user_roles();
