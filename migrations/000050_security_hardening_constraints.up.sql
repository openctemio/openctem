-- =============================================================================
-- Migration 000050: Security Hardening CHECK Constraints
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds field-length limits, array-size limits, future-date prevention, and
-- self-reference prevention constraints.  These protect data integrity at
-- the database level, regardless of application-layer validation.
--
-- All constraints use DO $$ blocks with EXCEPTION handling for idempotency.
-- =============================================================================

-- =============================================================================
-- 1. Field Length Limits
-- =============================================================================

-- asset_services: banner max 4096 chars
DO $$ BEGIN
    ALTER TABLE asset_services
        ADD CONSTRAINT check_banner_length
        CHECK (banner IS NULL OR length(banner) <= 4096);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- asset_services: cpe max 500 chars
DO $$ BEGIN
    ALTER TABLE asset_services
        ADD CONSTRAINT check_cpe_length
        CHECK (cpe IS NULL OR length(cpe) <= 500);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- asset_state_history: old_value max 2048 chars
DO $$ BEGIN
    ALTER TABLE asset_state_history
        ADD CONSTRAINT check_old_value_length
        CHECK (old_value IS NULL OR length(old_value) <= 2048);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- asset_state_history: new_value max 2048 chars
DO $$ BEGIN
    ALTER TABLE asset_state_history
        ADD CONSTRAINT check_new_value_length
        CHECK (new_value IS NULL OR length(new_value) <= 2048);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- asset_state_history: reason max 1024 chars
DO $$ BEGIN
    ALTER TABLE asset_state_history
        ADD CONSTRAINT check_reason_length
        CHECK (reason IS NULL OR length(reason) <= 1024);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- findings: attack_prerequisites max 1024 chars
DO $$ BEGIN
    ALTER TABLE findings
        ADD CONSTRAINT check_attack_prerequisites_length
        CHECK (attack_prerequisites IS NULL OR length(attack_prerequisites) <= 1024);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- =============================================================================
-- 2. Array Size Limits
-- =============================================================================

-- assets: compliance_scope array max 20 elements
DO $$ BEGIN
    ALTER TABLE assets
        ADD CONSTRAINT check_compliance_scope_size
        CHECK (compliance_scope IS NULL OR array_length(compliance_scope, 1) <= 20);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- findings: compliance_impact array max 20 elements
DO $$ BEGIN
    ALTER TABLE findings
        ADD CONSTRAINT check_compliance_impact_size
        CHECK (compliance_impact IS NULL OR array_length(compliance_impact, 1) <= 20);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- =============================================================================
-- 3. Future Date Prevention
-- =============================================================================

-- assets: exposure_changed_at cannot be in the future
DO $$ BEGIN
    ALTER TABLE assets
        ADD CONSTRAINT check_exposure_changed_at_not_future
        CHECK (exposure_changed_at IS NULL OR exposure_changed_at <= NOW() + INTERVAL '1 minute');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- asset_services: discovered_at cannot be in the future
DO $$ BEGIN
    ALTER TABLE asset_services
        ADD CONSTRAINT check_discovered_at_not_future
        CHECK (discovered_at IS NULL OR discovered_at <= NOW() + INTERVAL '1 minute');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- asset_services: last_seen_at cannot be in the future
DO $$ BEGIN
    ALTER TABLE asset_services
        ADD CONSTRAINT check_last_seen_at_not_future
        CHECK (last_seen_at IS NULL OR last_seen_at <= NOW() + INTERVAL '1 minute');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- asset_state_history: changed_at cannot be in the future
DO $$ BEGIN
    ALTER TABLE asset_state_history
        ADD CONSTRAINT check_changed_at_not_future
        CHECK (changed_at IS NULL OR changed_at <= NOW() + INTERVAL '1 minute');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- =============================================================================
-- 4. Self-Reference Prevention
-- =============================================================================

-- asset_components: parent cannot reference itself
DO $$ BEGIN
    ALTER TABLE asset_components
        ADD CONSTRAINT chk_no_self_parent
        CHECK (parent_component_id IS NULL OR parent_component_id != id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
