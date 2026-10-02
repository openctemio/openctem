-- late and stale did not exist before: they were online.
UPDATE sensors SET health = 'online' WHERE health IN ('late', 'stale');

ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS chk_sensors_health,
    ADD CONSTRAINT chk_sensors_health
        CHECK (health IN ('unknown', 'online', 'offline', 'error'));

ALTER TABLE sensors DROP CONSTRAINT IF EXISTS chk_sensors_heartbeat_interval;

COMMENT ON COLUMN sensors.health IS NULL;

ALTER TABLE sensors
    DROP COLUMN IF EXISTS control_reported_at,
    DROP COLUMN IF EXISTS reported_control,
    DROP COLUMN IF EXISTS heartbeat_due_at,
    DROP COLUMN IF EXISTS heartbeat_interval_seconds;
