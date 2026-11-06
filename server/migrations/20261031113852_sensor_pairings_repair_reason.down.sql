ALTER TABLE sensor_pairings DROP CONSTRAINT IF EXISTS chk_sensor_pairings_repair_reason;
ALTER TABLE sensor_pairings DROP COLUMN IF EXISTS repair_reason;
