-- The last refused attempt of a sensor on an open pairing code: shown on the
-- console's waiting step, so a refusal no longer reaches only the sensor's
-- log. Written only for a start whose signature verified and whose code is
-- an open expectation; read only by that expectation's organization.
ALTER TABLE sensor_pairings ADD COLUMN IF NOT EXISTS last_refusal varchar(32);
ALTER TABLE sensor_pairings ADD COLUMN IF NOT EXISTS last_refusal_at timestamptz;
ALTER TABLE sensor_pairings ADD COLUMN IF NOT EXISTS last_refusal_details jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sensor_pairings DROP CONSTRAINT IF EXISTS chk_sensor_pairings_last_refusal;
ALTER TABLE sensor_pairings ADD CONSTRAINT chk_sensor_pairings_last_refusal CHECK (
    (last_refusal IS NULL) = (last_refusal_at IS NULL)
    AND (last_refusal IS NULL
         OR last_refusal IN ('clock_skew', 'rate_limited', 'code_taken', 'key_busy', 'key_registered'))
    AND jsonb_typeof(last_refusal_details) = 'object'
);
