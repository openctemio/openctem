-- Migration 000227: platform administrators have no API keys (RFC-022)
--
-- Administrators sign in on /login with their linked users account and open
-- the console with a TOTP code. An admin API key was a second, MFA-less,
-- non-expiring way in with the same power, so admin keys are removed.
--
-- Expand-contract: every existing key is revoked here and new code no longer
-- reads or writes the columns. The columns stay (nullable) until a later
-- release drops them; a revoked placeholder is written instead of NULL so pods
-- still on the previous version, which scan these columns into strings, keep
-- working during a rolling deploy.
ALTER TABLE admin_users ALTER COLUMN api_key_hash DROP NOT NULL;
ALTER TABLE admin_users ALTER COLUMN api_key_prefix DROP NOT NULL;

UPDATE admin_users
SET api_key_hash = '!revoked',
    api_key_prefix = 'revoked-' || left(id::text, 8),
    updated_at = NOW()
WHERE api_key_hash IS DISTINCT FROM '!revoked';

-- Rows without a linked account were API-key-only identities; with keys gone
-- nothing can sign in as them. Deactivate rather than delete so the admin
-- audit trail that references them keeps its subject.
UPDATE admin_users SET is_active = FALSE, updated_at = NOW()
WHERE user_id IS NULL AND is_active;
