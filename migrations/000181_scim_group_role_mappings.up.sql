-- Per-tenant SCIM group → role mappings (RFC-009 Phase 9c refinement).
--
-- By default a SCIM group whose displayName matches a role name maps to that
-- role. Real IdPs name groups arbitrarily (e.g. "Acme-OpenCTEM-Admins"), so this
-- lets an admin map any group display name to a tenant role. group_name is
-- stored lowercased for case-insensitive matching. 'owner' is not assignable.
CREATE TABLE IF NOT EXISTS scim_group_role_mappings (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_name VARCHAR(255) NOT NULL,
    role       VARCHAR(20) NOT NULL,

    PRIMARY KEY (tenant_id, group_name),
    CONSTRAINT chk_scim_mapping_role CHECK (role IN ('admin', 'member', 'viewer'))
);
