ALTER TABLE sensor_pairings DROP CONSTRAINT IF EXISTS chk_sensor_pairings_last_refusal;
ALTER TABLE sensor_pairings DROP COLUMN IF EXISTS last_refusal_details;
ALTER TABLE sensor_pairings DROP COLUMN IF EXISTS last_refusal_at;
ALTER TABLE sensor_pairings DROP COLUMN IF EXISTS last_refusal;
