-- Reverts 001076: sensors go back to the gates they had before per-sensor
-- grants (poll, zone, tool, capability, local policy).
SET lock_timeout = '5s';

DROP TRIGGER IF EXISTS trigger_sensor_grants_default ON sensors;
DROP FUNCTION IF EXISTS sensor_grants_default();
DROP TABLE IF EXISTS sensor_grants;
