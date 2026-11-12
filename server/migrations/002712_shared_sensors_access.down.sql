ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_shared_sensors_access;
ALTER TABLE tenants DROP COLUMN IF EXISTS shared_sensors_access;
DELETE FROM platform_settings WHERE key = 'shared_sensors';
