DROP INDEX IF EXISTS idx_sensors_tenant_sdk_version;

ALTER TABLE sensors
    DROP COLUMN IF EXISTS sensor_build_time,
    DROP COLUMN IF EXISTS sensor_commit,
    DROP COLUMN IF EXISTS sensor_product,
    DROP COLUMN IF EXISTS sdk_version,
    DROP COLUMN IF EXISTS sdk_name;

DROP INDEX IF EXISTS idx_commands_sensor_activity;

DROP TABLE IF EXISTS sensor_events;
