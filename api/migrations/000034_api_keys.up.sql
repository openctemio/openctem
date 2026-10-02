-- =============================================================================
-- Migration 000034: API Keys
-- OpenCTEM OSS Edition
-- =============================================================================
-- User and tenant API keys for programmatic access.
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Owner
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,       -- NULL = tenant-level key

    -- Identity
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Key
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    key_prefix VARCHAR(10) NOT NULL,                           -- First 8 chars for identification

    -- Permissions
    scopes TEXT[] DEFAULT '{}',                                -- API scopes/permissions
    rate_limit INTEGER DEFAULT 1000,                           -- Requests per hour

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active',

    -- Expiration
    expires_at TIMESTAMPTZ,                                    -- NULL = never expires

    -- Usage Tracking
    last_used_at TIMESTAMPTZ,
    last_used_ip VARCHAR(45),
    use_count BIGINT NOT NULL DEFAULT 0,

    -- Audit
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revoked_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Constraints
    CONSTRAINT chk_api_key_status CHECK (status IN ('active', 'expired', 'revoked')),
    CONSTRAINT unique_api_key_name UNIQUE (tenant_id, name)
);

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(tenant_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_scopes ON api_keys USING GIN(scopes);

-- =============================================================================
-- Trigger
-- =============================================================================

CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE api_keys IS 'User and tenant API keys for programmatic access';
COMMENT ON COLUMN api_keys.user_id IS 'NULL = tenant-level key, otherwise user-level key';
COMMENT ON COLUMN api_keys.key_hash IS 'SHA-256 hash of the API key';
COMMENT ON COLUMN api_keys.key_prefix IS 'First 8 characters for identification (e.g., oct_xxxxx)';
COMMENT ON COLUMN api_keys.scopes IS 'API scopes/permissions: read:assets, write:scans, etc.';
