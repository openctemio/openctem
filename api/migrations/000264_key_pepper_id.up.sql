-- Which pepper each stored token hash was made with
-- (docs/deployment/encryption-key-rotation.md).
--
-- oct_ API keys, SCIM tokens and sensor keys are stored as HMAC(pepper, key).
-- The pepper comes from APP_ENCRYPTION_KEY (or SENSOR_KEY_PEPPER), so after
-- the key rotates the hashes made with the old one verify only while the old
-- key is listed in APP_ENCRYPTION_KEY_PREVIOUS. The server re-hashes such a
-- token with the current pepper the next time it is used and records the
-- pepper here; `rekey -status` counts the active tokens whose pepper is not
-- the current one, and APP_ENCRYPTION_KEY_PREVIOUS can be removed at zero.
--
-- key_pepper_id is a public identifier of the pepper
-- (HMAC(pepper, "openctem/pepper-id/v1"), 16 hex), never the pepper. NULL
-- means "made before this column existed": unknown, counted as old.
-- Additive, nullable, no backfill.

ALTER TABLE api_keys        ADD COLUMN IF NOT EXISTS key_pepper_id TEXT;
ALTER TABLE scim_tokens     ADD COLUMN IF NOT EXISTS key_pepper_id TEXT;
ALTER TABLE sensors         ADD COLUMN IF NOT EXISTS key_pepper_id TEXT;
ALTER TABLE sensor_api_keys ADD COLUMN IF NOT EXISTS key_pepper_id TEXT;
