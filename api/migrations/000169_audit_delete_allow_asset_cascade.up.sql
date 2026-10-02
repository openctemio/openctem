-- The asset_state_history.asset_id FK is ON DELETE CASCADE, but
-- prevent_recent_audit_delete() (migration 000051) blocks deleting any history
-- row younger than 30 days. Once the state-history writer started recording
-- 'appeared'/'status_changed' events, deleting an asset would cascade into its
-- fresh history rows and the trigger would raise — making asset deletion fail.
--
-- Fix: only block DIRECT deletion of a recent audit row while its asset still
-- exists (the anti-tampering case). When the parent asset row is already gone
-- — i.e. this DELETE is the FK cascade from removing the asset — allow it.
-- During an ON DELETE CASCADE the parent row is removed before the child
-- BEFORE DELETE trigger fires, so the EXISTS check is false for cascades.
CREATE OR REPLACE FUNCTION prevent_recent_audit_delete()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.changed_at > NOW() - INTERVAL '30 days'
       AND EXISTS (SELECT 1 FROM assets WHERE id = OLD.asset_id) THEN
        RAISE EXCEPTION 'Cannot delete asset_state_history records less than 30 days old (changed_at: %). Use retention jobs for cleanup.', OLD.changed_at;
        RETURN NULL;
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;
