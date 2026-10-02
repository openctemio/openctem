-- =============================================================================
-- Migration 043: Admin Users & Audit Logs
-- OpenCTEM OSS Edition
-- =============================================================================
-- Platform-level admin users with API key authentication.
-- Separate from tenant users - used for system administration.
-- =============================================================================

-- =============================================================================
-- Admin Users
-- =============================================================================

CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    api_key_hash VARCHAR(255) NOT NULL,
    api_key_prefix VARCHAR(20) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'readonly',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    -- Usage Tracking
    last_used_at TIMESTAMPTZ,
    last_used_ip VARCHAR(45),

    -- Security: Failed Login Tracking
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_failed_login_at TIMESTAMPTZ,
    last_failed_login_ip VARCHAR(45),

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_admin_role CHECK (role IN ('super_admin', 'ops_admin', 'readonly')),
    CONSTRAINT uq_admin_email UNIQUE (email),
    CONSTRAINT uq_admin_api_key_prefix UNIQUE (api_key_prefix)
);

COMMENT ON TABLE admin_users IS 'Platform admin users with API key authentication';
COMMENT ON COLUMN admin_users.api_key_prefix IS 'First 8 chars of API key for fast lookup';
COMMENT ON COLUMN admin_users.failed_login_count IS 'Tracks failed auth attempts for account lockout';

-- =============================================================================
-- Admin Audit Logs
-- =============================================================================

CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID REFERENCES admin_users(id) ON DELETE SET NULL,
    admin_email VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    resource_name VARCHAR(255),

    -- Request Details
    request_method VARCHAR(10),
    request_path VARCHAR(500),
    request_body JSONB,
    response_status INTEGER,

    -- Client Info
    ip_address VARCHAR(45),
    user_agent TEXT,

    -- Result
    success BOOLEAN NOT NULL DEFAULT TRUE,
    error_message TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE admin_audit_logs IS 'Immutable audit trail for admin actions';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Admin Users
CREATE INDEX IF NOT EXISTS idx_admin_users_email ON admin_users(email);
CREATE INDEX IF NOT EXISTS idx_admin_users_prefix ON admin_users(api_key_prefix);
CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role);
CREATE INDEX IF NOT EXISTS idx_admin_users_active ON admin_users(is_active) WHERE is_active = TRUE;

-- Admin Audit Logs
CREATE INDEX IF NOT EXISTS idx_admin_audit_admin ON admin_audit_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_admin_audit_resource ON admin_audit_logs(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_success ON admin_audit_logs(success) WHERE success = FALSE;
CREATE INDEX IF NOT EXISTS idx_admin_audit_email ON admin_audit_logs(admin_email);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_admin_users_updated_at ON admin_users;
CREATE TRIGGER trigger_admin_users_updated_at
    BEFORE UPDATE ON admin_users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
