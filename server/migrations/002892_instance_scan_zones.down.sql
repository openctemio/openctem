ALTER TABLE commands DROP CONSTRAINT IF EXISTS chk_commands_instance_scan_zone_shared;
ALTER TABLE commands DROP COLUMN IF EXISTS instance_scan_zone_id;
DROP TABLE IF EXISTS instance_scan_zone_tenants;
DROP TRIGGER IF EXISTS trg_instance_scan_zone_sensor_is_shared ON instance_scan_zone_sensors;
DROP TABLE IF EXISTS instance_scan_zone_sensors;
DROP FUNCTION IF EXISTS instance_scan_zone_sensor_is_shared();
DROP TABLE IF EXISTS instance_scan_zones;
