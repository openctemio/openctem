-- Shared sensors enrolled with a token keep their rows; only the pairing
-- history that has no tenant goes.
DELETE FROM sensor_pairings WHERE instance_token_id IS NOT NULL;

ALTER TABLE sensor_pairings DROP CONSTRAINT chk_sensor_pairings_bound;
ALTER TABLE sensor_pairings ADD CONSTRAINT chk_sensor_pairings_bound
    CHECK (status NOT IN ('approved', 'completed') OR (tenant_id IS NOT NULL AND sensor_id IS NOT NULL));
ALTER TABLE sensor_pairings DROP CONSTRAINT chk_sensor_pairings_instance_no_tenant;
DROP INDEX IF EXISTS ux_sensor_pairings_instance_token;
ALTER TABLE sensor_pairings DROP COLUMN instance_token_id;

DROP TABLE instance_enrollment_tokens;
