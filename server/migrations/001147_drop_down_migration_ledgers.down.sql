-- Recreates the two tables empty, as 000942 and 000945 left them. Their rows
-- are not restored (they are in the pre-upgrade backup).
CREATE TABLE IF NOT EXISTS priority_rule_safety_report (
    rule_id        UUID PRIMARY KEY,
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_name      VARCHAR(100) NOT NULL,
    priority_class VARCHAR(2) NOT NULL,
    reason         TEXT NOT NULL,
    conditions     JSONB,
    disabled_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
COMMENT ON TABLE priority_rule_safety_report IS
    'Priority override rules migration 000942 switched off because their conditions could not be valid (B17). Read-only record for operators.';

CREATE TABLE IF NOT EXISTS role_permissions_admin_only_stripped (
    role_id       UUID         NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tenant_id     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL,
    holders       INTEGER      NOT NULL,
    stripped_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);
COMMENT ON TABLE role_permissions_admin_only_stripped IS
    'Report of admin-only permissions removed from custom roles by migration 000945 (settings decision B1); read by the down migration';
