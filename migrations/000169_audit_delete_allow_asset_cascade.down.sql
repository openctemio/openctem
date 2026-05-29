-- Restore the unconditional 30-day deletion block (note: this reintroduces the
-- bug where deleting an asset with recent state-history rows fails).
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
