-- Revert Migration 000227. Revoked keys are not restored and deactivated rows
-- stay deactivated. Rows inserted without a key get a revoked placeholder so
-- the NOT NULL constraints can be put back.
UPDATE admin_users
SET api_key_hash = COALESCE(api_key_hash, '!revoked'),
    api_key_prefix = COALESCE(api_key_prefix, 'revoked-' || left(id::text, 8));
ALTER TABLE admin_users ALTER COLUMN api_key_hash SET NOT NULL;
ALTER TABLE admin_users ALTER COLUMN api_key_prefix SET NOT NULL;
