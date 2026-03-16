-- Tenant Identity Providers
-- Per-tenant SSO configuration for Entra ID, Okta, Google Workspace, etc.

CREATE TABLE IF NOT EXISTS tenant_identity_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL,        -- 'entra_id', 'okta', 'google_workspace'
    display_name VARCHAR(255) NOT NULL,   -- 'Company Entra ID'
    client_id VARCHAR(500) NOT NULL,
    client_secret_encrypted TEXT NOT NULL, -- AES-256-GCM encrypted
    issuer_url VARCHAR(500),              -- OIDC issuer URL (optional)
    tenant_identifier VARCHAR(255),       -- Azure AD tenant ID, Okta org URL, etc.
    scopes TEXT[] DEFAULT ARRAY['openid','email','profile','User.Read'],
    allowed_domains TEXT[],               -- Restrict to specific email domains
    auto_provision BOOLEAN DEFAULT true,  -- Auto-create user on first SSO login
    default_role VARCHAR(50) DEFAULT 'member', -- Default role for auto-provisioned users
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    CONSTRAINT uq_tenant_provider UNIQUE(tenant_id, provider)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_tip_tenant_id ON tenant_identity_providers(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tip_provider ON tenant_identity_providers(provider);
CREATE INDEX IF NOT EXISTS idx_tip_active ON tenant_identity_providers(tenant_id, is_active) WHERE is_active = true;

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_tip_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TRIGGER trg_tip_updated_at
        BEFORE UPDATE ON tenant_identity_providers
        FOR EACH ROW EXECUTE FUNCTION update_tip_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
