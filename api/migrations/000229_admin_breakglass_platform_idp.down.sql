-- Revert Migration 000229.
DROP TABLE IF EXISTS admin_idp_login_states;
DROP TABLE IF EXISTS platform_identity_provider;

ALTER TABLE admin_audit_logs DROP COLUMN IF EXISTS severity;
ALTER TABLE admin_sessions DROP COLUMN IF EXISTS auth_method;

DROP INDEX IF EXISTS idx_admin_users_idp_binding;
ALTER TABLE admin_users DROP CONSTRAINT IF EXISTS chk_admin_users_idp_binding_pair;
ALTER TABLE admin_users DROP CONSTRAINT IF EXISTS chk_admin_users_break_glass_local;
ALTER TABLE admin_users
    DROP COLUMN IF EXISTS idp_bound_at,
    DROP COLUMN IF EXISTS idp_subject,
    DROP COLUMN IF EXISTS idp_issuer,
    DROP COLUMN IF EXISTS password_change_required,
    DROP COLUMN IF EXISTS break_glass_tested_at,
    DROP COLUMN IF EXISTS is_break_glass;
