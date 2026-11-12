-- scope_name_exceptions (up): per-organization exceptions to the platform's
-- government and military name rule (docs/rfcs/RFC-154-blocked-target-names.md).
-- Written only by the platform console; the guardrails read the live rows.
CREATE TABLE IF NOT EXISTS scope_name_exceptions (
    id                  UUID         PRIMARY KEY,
    tenant_id           UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name                VARCHAR(253) NOT NULL,
    include_subdomains  BOOLEAN      NOT NULL DEFAULT FALSE,
    reason              TEXT         NOT NULL,
    authorization_ref   VARCHAR(500) NOT NULL,
    granted_by          UUID         REFERENCES admin_users(id) ON DELETE SET NULL,
    granted_by_email    VARCHAR(320) NOT NULL DEFAULT '',
    granted_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ  NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revoked_by_email    VARCHAR(320),
    revoke_reason       TEXT,
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT scope_name_exceptions_name_lower CHECK (name = LOWER(name) AND name <> '')
);

-- One live exception per organization and name.
CREATE UNIQUE INDEX IF NOT EXISTS uq_scope_name_exceptions_live
    ON scope_name_exceptions (tenant_id, name) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_scope_name_exceptions_tenant
    ON scope_name_exceptions (tenant_id);

COMMENT ON TABLE scope_name_exceptions IS
    'Platform-granted, expiring exceptions to the government and military scope rule, one organization and one name each.';

-- Changing the blocked-names policy and its exceptions is a platform owner
-- permission (the code gives the owner the whole catalog; this row mirrors it).
INSERT INTO platform_role_permissions (role_id, permission)
SELECT r.id, 'platform.settings.scope_guardrails'
FROM platform_roles r
WHERE r.key = 'platform_owner'
ON CONFLICT DO NOTHING;
