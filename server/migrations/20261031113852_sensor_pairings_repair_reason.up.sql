-- Why an administrator started a re-pair from the console (the re-pair
-- dialog). Set only on a reverse-mode request that targets an existing
-- sensor; shown on the approval screen, audited and on the timeline.
ALTER TABLE sensor_pairings ADD COLUMN IF NOT EXISTS repair_reason varchar(32);
ALTER TABLE sensor_pairings DROP CONSTRAINT IF EXISTS chk_sensor_pairings_repair_reason;
ALTER TABLE sensor_pairings ADD CONSTRAINT chk_sensor_pairings_repair_reason CHECK (
    repair_reason IS NULL
    OR (repair_sensor_id IS NOT NULL
        AND repair_reason IN ('lost_identity', 'host_moved', 'key_compromised', 'install_method'))
);
