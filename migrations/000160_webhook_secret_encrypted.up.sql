-- Replaces integration_scm_extensions.webhook_secret (VARCHAR plaintext)
-- with webhook_secret_encrypted (BYTEA) so that if a future feature
-- starts populating the column the bytes on disk are AES-GCM ciphertext
-- rather than plaintext. Audit flagged the old column as a DB-leak
-- vector: an attacker with read access to the database would see the
-- HMAC secret needed to forge valid SCM webhooks.
--
-- The current codebase never populates the column at runtime
-- (SetWebhook has no non-test callers as of migration date), so the
-- back-fill is a simple "copy to encrypted slot as NULL" — no live
-- rotation needed. If an operator HAS pre-seeded secrets outside the
-- app (direct SQL), this migration drops them; those integrations
-- need to re-trigger the SCM webhook provisioning flow to repopulate.

BEGIN;

ALTER TABLE integration_scm_extensions
    ADD COLUMN IF NOT EXISTS webhook_secret_encrypted BYTEA;

-- Intentionally NOT back-filling from webhook_secret: the plaintext
-- column's values (if any exist in older deployments) are considered
-- compromised once they've ever been on disk unencrypted. Operators
-- re-trigger webhook provisioning after this migration.
ALTER TABLE integration_scm_extensions
    DROP COLUMN IF EXISTS webhook_secret;

COMMENT ON COLUMN integration_scm_extensions.webhook_secret_encrypted IS
    'AES-256-GCM ciphertext of the SCM webhook HMAC secret, produced by pkg/crypto.Encryptor with APP_ENCRYPTION_KEY';

COMMIT;
