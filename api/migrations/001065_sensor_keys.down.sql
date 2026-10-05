-- Reverts 001065. Key-bound sensors cannot authenticate after this (they have
-- no bearer key); revoke them first or accept that they must be re-created.
SET lock_timeout = '5s';
DROP TABLE IF EXISTS sensor_keys;
ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_auth_kind;
ALTER TABLE sensors DROP COLUMN IF EXISTS auth_kind;
