ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS chk_exposure_events_peak_severity;
ALTER TABLE exposure_events DROP COLUMN IF EXISTS peak_severity;
