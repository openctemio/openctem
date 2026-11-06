-- What a step run ran with (research/426 P0.3): the standard params the
-- platform dispatched with their source, and what the sensor reported it ran
-- with. Nullable jsonb: no table rewrite, old rows stay NULL.
ALTER TABLE scan_run_steps ADD COLUMN IF NOT EXISTS effective_config jsonb;
ALTER TABLE scan_run_steps ADD COLUMN IF NOT EXISTS sensor_settings jsonb;
