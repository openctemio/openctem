-- Reverses 000256_sensor_identity_signals.up.sql.

DROP INDEX IF EXISTS idx_sensors_identity_cloned;

ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS sensors_instance_state_object;

ALTER TABLE sensors
    DROP COLUMN IF EXISTS identity_cloned_at,
    DROP COLUMN IF EXISTS instance_state,
    DROP COLUMN IF EXISTS instance_id,
    DROP COLUMN IF EXISTS api_key_last_used_ip,
    DROP COLUMN IF EXISTS api_key_last_used_at;
