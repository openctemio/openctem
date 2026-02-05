-- =============================================================================
-- Migration 000036: Settings
-- OpenCTEM OSS Edition
-- =============================================================================
-- System and tenant settings with typed values.
-- =============================================================================

CREATE TABLE IF NOT EXISTS settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Scope (NULL tenant_id = system-wide)
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,

    -- Key
    key VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL DEFAULT 'general',

    -- Value (typed)
    value_type VARCHAR(20) NOT NULL DEFAULT 'string',
    value_string TEXT,
    value_int BIGINT,
    value_float DOUBLE PRECISION,
    value_bool BOOLEAN,
    value_json JSONB,

    -- Metadata
    description TEXT,
    is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    is_readonly BOOLEAN NOT NULL DEFAULT FALSE,

    -- Audit
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_setting_value_type CHECK (value_type IN ('string', 'int', 'float', 'bool', 'json')),
    CONSTRAINT unique_setting_key UNIQUE NULLS NOT DISTINCT (tenant_id, key)
);

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_settings_tenant ON settings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category);
CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);
CREATE INDEX IF NOT EXISTS idx_settings_system ON settings(key) WHERE tenant_id IS NULL;

-- =============================================================================
-- Trigger
-- =============================================================================

CREATE TRIGGER update_settings_updated_at
    BEFORE UPDATE ON settings
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- Seed Default System Settings
-- =============================================================================

INSERT INTO settings (tenant_id, key, category, value_type, value_bool, description) VALUES
(NULL, 'registration_enabled', 'auth', 'bool', TRUE, 'Allow new user registration'),
(NULL, 'email_verification_required', 'auth', 'bool', TRUE, 'Require email verification for new accounts'),
(NULL, 'mfa_enabled', 'auth', 'bool', FALSE, 'Enable multi-factor authentication'),
(NULL, 'password_min_length', 'auth', 'int', NULL, 'Minimum password length')
ON CONFLICT DO NOTHING;

UPDATE settings SET value_int = 8 WHERE key = 'password_min_length' AND value_int IS NULL;

INSERT INTO settings (tenant_id, key, category, value_type, value_int, description) VALUES
(NULL, 'session_timeout_hours', 'auth', 'int', 24, 'Session timeout in hours'),
(NULL, 'max_sessions_per_user', 'auth', 'int', 5, 'Maximum concurrent sessions per user'),
(NULL, 'api_rate_limit_per_hour', 'api', 'int', 1000, 'Default API rate limit per hour'),
(NULL, 'max_file_upload_mb', 'storage', 'int', 100, 'Maximum file upload size in MB'),
(NULL, 'audit_log_retention_days', 'compliance', 'int', 365, 'Audit log retention in days')
ON CONFLICT DO NOTHING;

INSERT INTO settings (tenant_id, key, category, value_type, value_string, description) VALUES
(NULL, 'default_timezone', 'general', 'string', 'UTC', 'Default timezone'),
(NULL, 'default_language', 'general', 'string', 'en', 'Default language'),
(NULL, 'support_email', 'general', 'string', 'support@example.com', 'Support email address')
ON CONFLICT DO NOTHING;

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE settings IS 'System and tenant settings with typed values';
COMMENT ON COLUMN settings.tenant_id IS 'NULL = system-wide setting';
COMMENT ON COLUMN settings.value_type IS 'Value type: string, int, float, bool, json';
COMMENT ON COLUMN settings.is_secret IS 'TRUE if value should be masked in UI';
