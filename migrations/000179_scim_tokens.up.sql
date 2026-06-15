-- SCIM 2.0 provisioning bearer tokens (RFC-009 Phase 9a).
--
-- One (or more) per-tenant bearer token an IdP (Okta/Azure AD) presents to the
-- /scim/v2 endpoints. Only the peppered HMAC-SHA256 hash is stored — the
-- plaintext (oct_scim_...) is shown once at creation. A token belongs to exactly
-- one tenant, so SCIM requests are tenant-isolated by construction.
CREATE TABLE IF NOT EXISTS scim_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    token_hash   VARCHAR(128) NOT NULL UNIQUE,
    token_prefix VARCHAR(20) NOT NULL,
    status       VARCHAR(20) NOT NULL DEFAULT 'active',
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    CONSTRAINT chk_scim_token_status CHECK (status IN ('active', 'revoked'))
);

CREATE INDEX IF NOT EXISTS idx_scim_tokens_tenant ON scim_tokens (tenant_id, status);
