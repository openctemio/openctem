-- =============================================================================
-- Migration 000051 DOWN: Drop Audit Protection Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS check_finding_exposure_consistency ON findings;
DROP FUNCTION IF EXISTS log_exposure_inconsistency();

DROP TRIGGER IF EXISTS prevent_recent_audit_delete ON asset_state_history;
DROP FUNCTION IF EXISTS prevent_recent_audit_delete();

DROP TRIGGER IF EXISTS prevent_audit_history_update ON asset_state_history;
DROP FUNCTION IF EXISTS prevent_audit_update();
