-- SCIM 2.0 Groups (RFC-009 Phase 9c).
--
-- An IdP (Okta/Azure AD) pushes Groups via SCIM; group membership drives the
-- user's tenant role. A group whose display_name (case-insensitive) matches a
-- tenant role (admin/member/viewer) maps its members to that role; the
-- effective role is the highest such group a user belongs to, else 'member'.
-- 'owner' is never assignable via SCIM.
CREATE TABLE IF NOT EXISTS scim_groups (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name VARCHAR(255) NOT NULL,
    external_id  VARCHAR(255),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_scim_groups_tenant_name UNIQUE (tenant_id, display_name)
);

CREATE TABLE IF NOT EXISTS scim_group_members (
    group_id UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_groups_tenant ON scim_groups (tenant_id);
CREATE INDEX IF NOT EXISTS idx_scim_group_members_user ON scim_group_members (user_id);
