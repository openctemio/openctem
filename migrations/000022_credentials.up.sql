-- =============================================================================
-- Migration 022: Credentials
-- OpenCTEM OSS Edition
-- =============================================================================
-- Secure credential storage for external integrations.
-- Supports multiple credential types: API keys, tokens, SSH keys, cloud IAM roles.

CREATE TABLE IF NOT EXISTS credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Credential identification
    name VARCHAR(255) NOT NULL,
    credential_type VARCHAR(50) NOT NULL,
    description TEXT,

    -- Encrypted credential data (AES-256-GCM encrypted JSON)
    -- Structure depends on credential_type:
    -- api_key: {"key": "xxx"}
    -- bearer_token: {"token": "xxx"}
    -- basic_auth: {"username": "xxx", "password": "xxx"}
    -- ssh_key: {"private_key": "xxx", "passphrase": "xxx"}
    -- aws_role: {"role_arn": "xxx", "external_id": "xxx"}
    -- gcp_service_account: {"json_key": "xxx"}
    -- azure_service_principal: {"tenant_id": "xxx", "client_id": "xxx", "client_secret": "xxx"}
    -- github_app: {"app_id": "xxx", "installation_id": "xxx", "private_key": "xxx"}
    -- gitlab_token: {"token": "xxx"}
    encrypted_data BYTEA NOT NULL,

    -- Key management
    key_version INTEGER NOT NULL DEFAULT 1,
    encryption_algorithm VARCHAR(20) NOT NULL DEFAULT 'AES-256-GCM',

    -- Metadata
    last_used_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,

    -- Audit fields
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_credentials_type CHECK (credential_type IN (
        'api_key',
        'bearer_token',
        'basic_auth',
        'ssh_key',
        'aws_role',
        'gcp_service_account',
        'azure_service_principal',
        'github_app',
        'gitlab_token'
    )),
    CONSTRAINT credentials_name_unique UNIQUE (tenant_id, name)
);

COMMENT ON TABLE credentials IS 'Secure storage for external integration credentials';
COMMENT ON COLUMN credentials.credential_type IS 'Type of credential: api_key, bearer_token, basic_auth, ssh_key, aws_role, etc.';
COMMENT ON COLUMN credentials.encrypted_data IS 'AES-256-GCM encrypted JSON containing credential data';
COMMENT ON COLUMN credentials.key_version IS 'Version of encryption key used, for key rotation support';
COMMENT ON COLUMN credentials.expires_at IS 'When this credential expires and needs rotation';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_credentials_tenant ON credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_credentials_expires ON credentials(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_credentials_created_at ON credentials(created_at DESC);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_credentials_updated_at ON credentials;
CREATE TRIGGER trigger_credentials_updated_at
    BEFORE UPDATE ON credentials
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

