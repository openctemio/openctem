-- The two-approver rule for accepting or dismissing an exposure was decided on
-- its current severity, which a re-ingest overwrites: re-reporting a critical
-- exposure as low let one person accept it alone. peak_severity keeps the
-- highest severity the exposure ever had; the rule reads the higher of the two.
-- NULL means "never lowered": readers use COALESCE(peak_severity, severity), so
-- no backfill (and no table rewrite) is needed on a populated table.
ALTER TABLE exposure_events ADD COLUMN IF NOT EXISTS peak_severity VARCHAR(20);
ALTER TABLE exposure_events DROP CONSTRAINT IF EXISTS chk_exposure_events_peak_severity;
ALTER TABLE exposure_events ADD CONSTRAINT chk_exposure_events_peak_severity
    CHECK (peak_severity IS NULL OR peak_severity IN ('critical', 'high', 'medium', 'low', 'info')) NOT VALID;
