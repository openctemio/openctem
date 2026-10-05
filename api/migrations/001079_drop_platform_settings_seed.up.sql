-- expand-contract-ok: contract step; no released code reads the seeded platform settings rows or the typed value columns.
-- Drop the seeded platform settings nothing reads (legacy cleanup).
--
-- 000036 seeded twelve system-wide rows (tenant_id IS NULL) into `settings`:
-- registration_enabled, email_verification_required, mfa_enabled,
-- password_min_length, session_timeout_hours, max_sessions_per_user,
-- api_rate_limit_per_hour, max_file_upload_mb, audit_log_retention_days,
-- default_timezone, default_language, support_email. No code reads any of
-- them: the real controls are environment settings (AUTH_ALLOW_REGISTRATION,
-- AUTH_PASSWORD_MIN_LENGTH, rate limits, retention jobs) and the per-tenant
-- settings in tenants.settings. Editing a row changed nothing, which made
-- them inert controls.
--
-- The only reader of `settings` is the tenant storage resolver (key
-- 'storage_config', value_json). The typed value columns and the
-- is_secret / is_readonly flags were used only by the seed rows and go too.
--
-- The down migration restores the columns and the twelve rows with their
-- seeded values.
--
-- Tenant isolation: unchanged. Only system-wide rows (tenant_id IS NULL) are
-- deleted; no tenant row and no policy is touched.

DELETE FROM settings
WHERE tenant_id IS NULL
  AND key IN (
    'registration_enabled', 'email_verification_required', 'mfa_enabled',
    'password_min_length', 'session_timeout_hours', 'max_sessions_per_user',
    'api_rate_limit_per_hour', 'max_file_upload_mb', 'audit_log_retention_days',
    'default_timezone', 'default_language', 'support_email'
  );

ALTER TABLE settings
    DROP COLUMN IF EXISTS value_string,
    DROP COLUMN IF EXISTS value_int,
    DROP COLUMN IF EXISTS value_float,
    DROP COLUMN IF EXISTS value_bool,
    DROP COLUMN IF EXISTS is_secret,
    DROP COLUMN IF EXISTS is_readonly;
