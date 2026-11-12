DROP TRIGGER IF EXISTS trg_asset_owners_priority_update ON asset_owners;
DROP TRIGGER IF EXISTS trg_asset_owners_priority_delete ON asset_owners;
DROP TRIGGER IF EXISTS trg_asset_owners_priority_insert ON asset_owners;
DROP FUNCTION IF EXISTS finding_priority_enqueue_owner_row();
DROP FUNCTION IF EXISTS finding_priority_enqueue_owners();

-- Previous definitions (002220_scoring_versions).
DROP TRIGGER IF EXISTS trg_assets_priority_update ON assets;
CREATE TRIGGER trg_assets_priority_update
    AFTER UPDATE OF criticality, exposure, is_crown_jewel, deleted_at ON assets
    FOR EACH ROW
    WHEN (OLD.criticality IS DISTINCT FROM NEW.criticality
       OR OLD.exposure IS DISTINCT FROM NEW.exposure
       OR OLD.is_crown_jewel IS DISTINCT FROM NEW.is_crown_jewel
       OR (OLD.deleted_at IS NOT NULL AND NEW.deleted_at IS NULL))
    EXECUTE FUNCTION finding_priority_enqueue_asset_row();

DROP TRIGGER IF EXISTS trg_findings_priority_update ON findings;
CREATE TRIGGER trg_findings_priority_update
    AFTER UPDATE OF status, severity, asset_id ON findings
    FOR EACH ROW
    WHEN ((NOT is_open_finding_status(OLD.status) AND is_open_finding_status(NEW.status))
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.asset_id IS DISTINCT FROM NEW.asset_id)
    EXECUTE FUNCTION finding_priority_enqueue_finding_update();
