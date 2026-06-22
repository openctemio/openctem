-- SAML 2.0 Service Provider config, per tenant (RFC-009 Phase 9d/9e).
--
-- Stores the IdP side (entity id, SSO redirect URL, signing certificate) plus
-- provisioning policy. The SP entity id / ACS URL are derived at runtime from
-- the deployment host + org slug, so they are not stored. Disabled by default —
-- an operator must explicitly enable SAML login per tenant after validating it
-- against their IdP.
CREATE TABLE IF NOT EXISTS saml_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    idp_entity_id   TEXT NOT NULL,
    idp_sso_url     TEXT NOT NULL,
    idp_certificate TEXT NOT NULL,
    allowed_domains TEXT[] NOT NULL DEFAULT '{}',
    default_role    VARCHAR(20) NOT NULL DEFAULT 'member',
    auto_provision  BOOLEAN NOT NULL DEFAULT TRUE,
    enabled         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_saml_default_role CHECK (default_role IN ('admin', 'member', 'viewer'))
);
