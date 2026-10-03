-- The check_finding_exposure_consistency trigger (000051, fixed in 000085)
-- recorded an asset exposure CHANGE whenever a new finding's
-- is_internet_accessible differed from its asset's: change_type
-- internet_exposure_changed, old = the asset's value, new = the finding's.
-- The asset never changed. Those rows were read as real transitions by the
-- "What changed" feed, "Newly exposed assets" and the dashboard's
-- time-to-detect. Real exposure transitions are recorded by ingest when an
-- asset's own values change (processor_assets.go exposureTransitions).
--
-- Existing rows are left alone: asset_state_history is append-only. They are
-- recognisable by reason LIKE 'Finding % claims internet_accessible=%'.
DROP TRIGGER IF EXISTS check_finding_exposure_consistency ON findings;
DROP FUNCTION IF EXISTS log_exposure_inconsistency();
