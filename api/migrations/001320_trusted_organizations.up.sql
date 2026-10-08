-- Trusted organizations: a host organization trusts a named home
-- organization, and the home organization accepts. External members from
-- that home may then satisfy the host's SSO and 2FA policy with a session
-- from their home identity provider. Design: docs/rfcs/RFC-058-external-members.md.
CREATE TABLE tenant_trusts (
    id                   uuid PRIMARY KEY DEFAULT uuid_generate_v7(),
    host_tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    home_tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status               text NOT NULL DEFAULT 'requested',
    -- Highest role an external member from the home may hold in the host.
    max_role             text NOT NULL DEFAULT 'member',
    -- Accept a session from the home's identity provider as SSO here.
    accept_home_sso      boolean NOT NULL DEFAULT true,
    -- Accept it only when the provider proved a second factor (amr/acr,
    -- SAML AuthnContext).
    require_mfa_evidence boolean NOT NULL DEFAULT false,
    -- The home owner attests that its identity provider enforces MFA for
    -- everyone (set by the home only).
    home_attests_mfa     boolean NOT NULL DEFAULT false,
    -- External members from the home may create API keys here.
    allow_api_keys       boolean NOT NULL DEFAULT false,
    -- End of access proposed for new external members from the home.
    default_expiry_days  integer NULL,
    requested_by         uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    accepted_by          uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    accepted_at          timestamptz NULL,
    CONSTRAINT uq_tenant_trusts_pair UNIQUE (host_tenant_id, home_tenant_id),
    CONSTRAINT chk_tenant_trusts_not_self CHECK (host_tenant_id <> home_tenant_id),
    CONSTRAINT chk_tenant_trusts_status CHECK (status IN ('requested', 'active')),
    CONSTRAINT chk_tenant_trusts_max_role CHECK (max_role IN ('viewer', 'member')),
    CONSTRAINT chk_tenant_trusts_expiry CHECK (default_expiry_days IS NULL OR default_expiry_days BETWEEN 1 AND 365)
);

CREATE INDEX idx_tenant_trusts_home ON tenant_trusts (home_tenant_id);

COMMENT ON TABLE tenant_trusts IS
    'Host organization trusts a home organization (RFC-058); active once the home owner accepts.';

-- Whether the identity provider proved a second factor for this sign-in.
ALTER TABLE sessions ADD COLUMN mfa_evidence boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN sessions.mfa_evidence IS
    'The identity provider proved a second factor for this federated sign-in (OIDC amr/acr, SAML AuthnContext).';
