-- A held finding counts in no risk input of its asset
-- (docs/architecture/held-findings.md), so holding or releasing one changes
-- the asset's score: the finding update trigger of asset_risk_queue now also
-- watches verification_state, and the asset is queued for a rescore.
--
-- Live impact: DROP + CREATE TRIGGER take a short SHARE ROW EXCLUSIVE lock
-- on findings (catalog change only, no scan). The trigger fires per changed
-- row, as before; a bulk update that does not change verification_state
-- costs the same as before (measured in the pull request).
DROP TRIGGER IF EXISTS trg_findings_asset_risk_update ON findings;
CREATE TRIGGER trg_findings_asset_risk_update
    AFTER UPDATE OF status, severity, asset_id, branch_only, epss_score, is_in_kev,
        exploit_available, is_reachable, vex_status, verification_state ON findings
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.asset_id IS DISTINCT FROM NEW.asset_id
       OR OLD.branch_only IS DISTINCT FROM NEW.branch_only
       OR OLD.epss_score IS DISTINCT FROM NEW.epss_score
       OR OLD.is_in_kev IS DISTINCT FROM NEW.is_in_kev
       OR OLD.exploit_available IS DISTINCT FROM NEW.exploit_available
       OR OLD.is_reachable IS DISTINCT FROM NEW.is_reachable
       OR OLD.vex_status IS DISTINCT FROM NEW.vex_status
       OR OLD.verification_state IS DISTINCT FROM NEW.verification_state)
    EXECUTE FUNCTION asset_risk_enqueue_finding_update();
