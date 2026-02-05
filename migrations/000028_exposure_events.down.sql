-- =============================================================================
-- Migration 028: Exposure Events (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_exposure_events_updated_at ON exposure_events;

DROP TABLE IF EXISTS exposure_state_history;
DROP TABLE IF EXISTS exposure_events;

