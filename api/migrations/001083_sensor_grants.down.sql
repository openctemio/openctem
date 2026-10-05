-- Reverts 001083: sensors go back to the gates they had before per-sensor
-- grants (poll, zone, tool, capability, local policy).
SET lock_timeout = '5s';

DROP TRIGGER IF EXISTS trigger_sensor_grants_default ON sensors;
DROP FUNCTION IF EXISTS sensor_grants_default();
DROP TABLE IF EXISTS sensor_grants;
ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_trust_level;
ALTER TABLE sensors DROP COLUMN IF EXISTS trust_level;
