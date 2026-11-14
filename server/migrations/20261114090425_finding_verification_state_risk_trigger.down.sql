-- The trigger as asset_risk_queue defined it (verification_state not watched).
DROP TRIGGER IF EXISTS trg_findings_asset_risk_update ON findings;
CREATE TRIGGER trg_findings_asset_risk_update
    AFTER UPDATE OF status, severity, asset_id, branch_only, epss_score, is_in_kev,
        exploit_available, is_reachable, vex_status ON findings
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.asset_id IS DISTINCT FROM NEW.asset_id
       OR OLD.branch_only IS DISTINCT FROM NEW.branch_only
       OR OLD.epss_score IS DISTINCT FROM NEW.epss_score
       OR OLD.is_in_kev IS DISTINCT FROM NEW.is_in_kev
       OR OLD.exploit_available IS DISTINCT FROM NEW.exploit_available
       OR OLD.is_reachable IS DISTINCT FROM NEW.is_reachable
       OR OLD.vex_status IS DISTINCT FROM NEW.vex_status)
    EXECUTE FUNCTION asset_risk_enqueue_finding_update();
