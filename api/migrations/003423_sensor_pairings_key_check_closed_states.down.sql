-- Closed expectations without a key cannot satisfy the old check; they carry
-- nothing a sensor can use, so they are removed before it is restored.
DELETE FROM sensor_pairings WHERE status IN ('denied', 'expired') AND public_key IS NULL;
ALTER TABLE sensor_pairings DROP CONSTRAINT IF EXISTS chk_sensor_pairings_key;
ALTER TABLE sensor_pairings ADD CONSTRAINT chk_sensor_pairings_key CHECK (((status)::text = 'expecting'::text) = (public_key IS NULL));
