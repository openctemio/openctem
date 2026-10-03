-- Organization SSO changes made by a platform administrator wait for the
-- organization's owner (owner decision 2026-10-02, RFC-022).
--
-- The organization's SAML configuration and OIDC identity providers decide
-- who can sign in to it. A platform administrator who could install their own
-- IdP signing certificate (or their own OIDC client) could sign in as any
-- member, so a change submitted from the admin console is stored here and the
-- live config is left untouched until an owner of the organization approves
-- it. Approval applies the change in the same transaction that marks the row
-- approved; rejection or expiry discards it.
--
-- payload holds the submitted configuration WITHOUT secrets. An OIDC client
-- secret is held in secret_encrypted, encrypted with the same key as
-- tenant_identity_providers.client_secret_encrypted, and is cleared when the
-- change is decided.
CREATE TABLE IF NOT EXISTS sso_pending_changes (
    id                  UUID PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    kind                VARCHAR(32) NOT NULL,
    -- The identity provider an idp_update changes; NULL otherwise.
    target_id           UUID,
    payload             JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_encrypted    TEXT,
    status              VARCHAR(16) NOT NULL DEFAULT 'pending',
    requested_by_admin  UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    requested_by_email  VARCHAR(320) NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    decided_at          TIMESTAMPTZ,
    decided_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT chk_sso_pending_changes_kind
        CHECK (kind IN ('saml_config', 'idp_create', 'idp_update')),
    CONSTRAINT chk_sso_pending_changes_status
        CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'superseded'))
);

CREATE INDEX IF NOT EXISTS idx_sso_pending_changes_tenant_status
    ON sso_pending_changes (tenant_id, status, created_at DESC);

COMMENT ON TABLE sso_pending_changes IS
    'SSO configuration changes submitted by a platform administrator, awaiting approval by an owner of the organization';
COMMENT ON COLUMN sso_pending_changes.secret_encrypted IS
    'Encrypted OIDC client secret for idp_create/idp_update; cleared once the change is decided';
