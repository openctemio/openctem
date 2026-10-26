-- An expected pairing (an admin made the code first, no sensor key yet) can
-- be denied by the admin or expire unused. The old check tied "no key" to the
-- 'expecting' status alone, so both transitions failed: denying an expected
-- code returned an error, and the periodic sweep rolled back as soon as one
-- expected code expired, which stopped every pairing from ever expiring.
-- Closed states (denied, expired) may now have no key; open and approved
-- states keep their rule.
ALTER TABLE sensor_pairings DROP CONSTRAINT IF EXISTS chk_sensor_pairings_key;
ALTER TABLE sensor_pairings ADD CONSTRAINT chk_sensor_pairings_key CHECK (
    CASE status
        WHEN 'expecting' THEN public_key IS NULL
        WHEN 'denied' THEN TRUE
        WHEN 'expired' THEN TRUE
        ELSE public_key IS NOT NULL
    END
);
