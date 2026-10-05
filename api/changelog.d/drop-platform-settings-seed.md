### Removed: twelve seeded platform settings nothing read

- Migration 001079 deletes the system-wide rows 000036 seeded into
  `settings` (registration_enabled, email_verification_required, mfa_enabled,
  password_min_length, session_timeout_hours, max_sessions_per_user,
  api_rate_limit_per_hour, max_file_upload_mb, audit_log_retention_days,
  default_timezone, default_language, support_email) and the typed value
  columns only they used. No code read them; the real controls are the
  environment settings (`AUTH_ALLOW_REGISTRATION`, `AUTH_PASSWORD_MIN_LENGTH`,
  ...) and the per-organization settings.
- The `settings` table stays for the per-tenant file storage configuration.
- Upgrade in one step. The down migration restores the columns and rows.
