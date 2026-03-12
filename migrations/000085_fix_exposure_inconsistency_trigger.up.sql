-- Fix: log_exposure_inconsistency() trigger used 'exposure_inconsistency' as change_type,
-- which violates the chk_change_type CHECK constraint on asset_state_history.
-- Change to 'internet_exposure_changed' which is an allowed value.

CREATE OR REPLACE FUNCTION log_exposure_inconsistency()
RETURNS TRIGGER AS $$
DECLARE
    v_asset_internet BOOLEAN;
BEGIN
    IF NEW.asset_id IS NOT NULL AND NEW.is_internet_accessible IS NOT NULL THEN
        SELECT is_internet_accessible
        INTO v_asset_internet
        FROM assets
        WHERE id = NEW.asset_id AND tenant_id = NEW.tenant_id;

        IF v_asset_internet IS NOT NULL AND v_asset_internet != NEW.is_internet_accessible THEN
            INSERT INTO asset_state_history (
                tenant_id, asset_id, change_type, field,
                old_value, new_value, reason, source, changed_at
            ) VALUES (
                NEW.tenant_id,
                NEW.asset_id,
                'internet_exposure_changed',
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
