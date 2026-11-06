ALTER TABLE sensor_pairings DROP CONSTRAINT IF EXISTS chk_sensor_pairings_enrollment_tenant;
DROP INDEX IF EXISTS ix_sensor_pairings_enrollment_token;
ALTER TABLE sensor_pairings DROP COLUMN IF EXISTS enrollment_token_id;
DROP TABLE IF EXISTS sensor_enrollment_tokens;
