-- =============================================================================
-- Migration 000050 DOWN: Drop Security Hardening CHECK Constraints
-- =============================================================================

-- Self-reference prevention
ALTER TABLE asset_components DROP CONSTRAINT IF EXISTS chk_no_self_parent;

-- Future date prevention
ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS check_changed_at_not_future;
ALTER TABLE asset_services DROP CONSTRAINT IF EXISTS check_last_seen_at_not_future;
ALTER TABLE asset_services DROP CONSTRAINT IF EXISTS check_discovered_at_not_future;
ALTER TABLE assets DROP CONSTRAINT IF EXISTS check_exposure_changed_at_not_future;

-- Array size limits
ALTER TABLE findings DROP CONSTRAINT IF EXISTS check_compliance_impact_size;
ALTER TABLE assets DROP CONSTRAINT IF EXISTS check_compliance_scope_size;

-- Field length limits
ALTER TABLE findings DROP CONSTRAINT IF EXISTS check_attack_prerequisites_length;
ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS check_reason_length;
ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS check_new_value_length;
ALTER TABLE asset_state_history DROP CONSTRAINT IF EXISTS check_old_value_length;
ALTER TABLE asset_services DROP CONSTRAINT IF EXISTS check_cpe_length;
ALTER TABLE asset_services DROP CONSTRAINT IF EXISTS check_banner_length;
