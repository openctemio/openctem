ALTER TABLE sensors
    DROP CONSTRAINT IF EXISTS chk_sensors_config_health,
    DROP COLUMN IF EXISTS config_heartbeat_digest,
    DROP COLUMN IF EXISTS config_health,
    DROP COLUMN IF EXISTS config_report_digest;

DROP TABLE IF EXISTS sensor_config_reports;
