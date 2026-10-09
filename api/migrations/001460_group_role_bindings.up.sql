-- Team (access group) to role binding (owner decisions G1-G12).
-- A custom role bound to a team is held by every active member of the team.
-- Roles stay the only source of permissions; a team gains no permission set
-- of its own.

-- Composite keys so a binding can only join a group and a role of the same
-- organization. A system role has tenant_id NULL, so it can never match: the
-- schema itself refuses binding owner, admin, member, viewer or any other
-- built-in role.
ALTER TABLE groups ADD CONSTRAINT groups_id_tenant_key UNIQUE (id, tenant_id);
ALTER TABLE roles ADD CONSTRAINT roles_id_tenant_key UNIQUE (id, tenant_id);

CREATE TABLE group_role_bindings (
    tenant_id  UUID NOT NULL,
    group_id   UUID NOT NULL,
    role_id    UUID NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, role_id),
    FOREIGN KEY (group_id, tenant_id) REFERENCES groups (id, tenant_id) ON DELETE CASCADE,
    -- RESTRICT: a bound role cannot be deleted (ROLE_IN_USE).
    FOREIGN KEY (role_id, tenant_id) REFERENCES roles (id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX idx_group_role_bindings_role ON group_role_bindings (tenant_id, role_id);
COMMENT ON TABLE group_role_bindings IS
    'A custom role held by every active member of a team (decisions G1-G12). Roles stay the only source of permissions.';

-- One answer to "which roles does this person hold": their direct roles, and
-- the roles bound to the active teams they belong to (a membership past its
-- end date counts as gone at once, before the expiry controller removes it).
CREATE VIEW v_user_role_grants AS
    SELECT ur.tenant_id, ur.user_id, ur.role_id, 'direct'::text AS source, NULL::uuid AS group_id
    FROM user_roles ur
    UNION ALL
    SELECT g.tenant_id, gm.user_id, b.role_id, 'group'::text, g.id
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active
    JOIN group_role_bindings b ON b.group_id = g.id AND b.tenant_id = g.tenant_id
    WHERE gm.expires_at IS NULL OR gm.expires_at > now();
COMMENT ON VIEW v_user_role_grants IS
    'Roles a user holds in a tenant: direct (user_roles) and through teams (group_role_bindings). Read it to resolve permissions and full data access.';
