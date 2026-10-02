BEGIN;

ALTER TABLE integration_scm_extensions
    ADD COLUMN IF NOT EXISTS webhook_secret VARCHAR(255);

ALTER TABLE integration_scm_extensions
    DROP COLUMN IF EXISTS webhook_secret_encrypted;

COMMIT;
