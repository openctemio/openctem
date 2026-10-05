-- Restore the typed value columns and the twelve seeded platform settings
-- (values as seeded by 000036).

ALTER TABLE settings
    ADD COLUMN IF NOT EXISTS value_string TEXT,
    ADD COLUMN IF NOT EXISTS value_int BIGINT,
    ADD COLUMN IF NOT EXISTS value_float DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS value_bool BOOLEAN,
    ADD COLUMN IF NOT EXISTS is_secret BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_readonly BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN settings.is_secret IS 'TRUE if value should be masked in UI';

INSERT INTO settings (tenant_id, key, category, value_type, value_bool, description) VALUES
(NULL, 'registration_enabled', 'auth', 'bool', TRUE, 'Allow new user registration'),
(NULL, 'email_verification_required', 'auth', 'bool', TRUE, 'Require email verification for new accounts'),
(NULL, 'mfa_enabled', 'auth', 'bool', FALSE, 'Enable multi-factor authentication')
ON CONFLICT DO NOTHING;

INSERT INTO settings (tenant_id, key, category, value_type, value_int, description) VALUES
(NULL, 'password_min_length', 'auth', 'int', 8, 'Minimum password length'),
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
