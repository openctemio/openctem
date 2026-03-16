-- =============================================================================
-- Migration 000051: Audit Protection Triggers
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds database-level protections for audit trail integrity:
-- 1. prevent_audit_update    - blocks UPDATE on asset_state_history
-- 2. prevent_recent_audit_delete - blocks DELETE within 30 days
-- 3. log_exposure_inconsistency  - logs when finding exposure != asset exposure
-- =============================================================================

-- =============================================================================
-- 1. Prevent Updates to Audit History
-- =============================================================================
-- Audit records are immutable.  If you need to correct an entry, insert a
-- new record with the correct values.

CREATE OR REPLACE FUNCTION prevent_audit_update()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'UPDATE on asset_state_history is not allowed. Audit records are immutable. Insert a new record instead.';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS prevent_audit_history_update ON asset_state_history;
CREATE TRIGGER prevent_audit_history_update
    BEFORE UPDATE ON asset_state_history
    FOR EACH ROW
    EXECUTE FUNCTION prevent_audit_update();

-- =============================================================================
-- 2. Prevent Deletion of Recent Audit Records
-- =============================================================================
-- Records less than 30 days old cannot be deleted.  This gives a safety
-- window for forensic review.  Older records can be cleaned up by retention
-- jobs.

CREATE OR REPLACE FUNCTION prevent_recent_audit_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.changed_at > NOW() - INTERVAL '30 days' THEN
        RAISE EXCEPTION 'Cannot delete asset_state_history records less than 30 days old (changed_at: %). Use retention jobs for cleanup.', OLD.changed_at;
        RETURN NULL;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS prevent_recent_audit_delete ON asset_state_history;
CREATE TRIGGER prevent_recent_audit_delete
    BEFORE DELETE ON asset_state_history
    FOR EACH ROW
    EXECUTE FUNCTION prevent_recent_audit_delete();

-- =============================================================================
-- 3. Log Exposure Inconsistency Between Finding and Asset
-- =============================================================================
-- When a finding claims internet accessibility but the linked asset does not
-- (or vice versa), log a warning to asset_state_history for investigation.
-- This does NOT block the INSERT; it only records the inconsistency.

CREATE OR REPLACE FUNCTION log_exposure_inconsistency()
RETURNS TRIGGER AS $$
DECLARE
    v_asset_internet BOOLEAN;
BEGIN
    -- Only check if finding has an asset_id and claims internet accessibility
    IF NEW.asset_id IS NOT NULL AND NEW.is_internet_accessible IS NOT NULL THEN
        SELECT is_internet_accessible
        INTO v_asset_internet
        FROM assets
        WHERE id = NEW.asset_id AND tenant_id = NEW.tenant_id;

        -- Log if finding and asset disagree on internet accessibility
        IF v_asset_internet IS NOT NULL AND v_asset_internet != NEW.is_internet_accessible THEN
            INSERT INTO asset_state_history (
                tenant_id, asset_id, change_type, field,
                old_value, new_value, reason, source, changed_at
            ) VALUES (
                NEW.tenant_id,
                NEW.asset_id,
                'exposure_inconsistency',
                'is_internet_accessible',
                v_asset_internet::TEXT,
                NEW.is_internet_accessible::TEXT,
                format('Finding %s claims internet_accessible=%s but asset says %s',
                       NEW.id, NEW.is_internet_accessible, v_asset_internet),
                'system',
                NOW()
            );
        END IF;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS check_finding_exposure_consistency ON findings;
CREATE TRIGGER check_finding_exposure_consistency
    AFTER INSERT ON findings
    FOR EACH ROW
    EXECUTE FUNCTION log_exposure_inconsistency();
