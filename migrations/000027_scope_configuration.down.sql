-- =============================================================================
-- Migration 027: Scope Configuration (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_scan_schedules_updated_at ON scan_schedules;
DROP TRIGGER IF EXISTS trigger_scope_exclusions_updated_at ON scope_exclusions;
DROP TRIGGER IF EXISTS trigger_scope_targets_updated_at ON scope_targets;

DROP FUNCTION IF EXISTS expire_scope_exclusions();

DROP TABLE IF EXISTS scan_schedules;
DROP TABLE IF EXISTS scope_exclusions;
DROP TABLE IF EXISTS scope_targets;

