-- A finding's validation outcome is now a priority input: a re-check that
-- reproduced the finding ("reproducible") is exploitation evidence and sets
-- the P1 exploitation floor (priority model v2,
-- docs/architecture/priority-explainability.md). Queue a recompute when it
-- changes, like the other finding-level inputs (002945). Trigger DDL only: no
-- backfill, nothing is rewritten; the model version bump recomputes every
-- open finding once in the background.

DROP TRIGGER IF EXISTS trg_findings_priority_update ON findings;
CREATE TRIGGER trg_findings_priority_update
    AFTER UPDATE OF status, severity, asset_id, cve_id, vulnerability_id, cvss_score,
                    is_internet_accessible, is_network_accessible,
                    exposure_vector, data_exposure_risk, compliance_impact,
                    validation_outcome ON findings
    FOR EACH ROW
    WHEN ((NOT is_open_finding_status(OLD.status) AND is_open_finding_status(NEW.status))
       OR OLD.severity IS DISTINCT FROM NEW.severity
       OR OLD.asset_id IS DISTINCT FROM NEW.asset_id
       OR OLD.cve_id IS DISTINCT FROM NEW.cve_id
       OR OLD.vulnerability_id IS DISTINCT FROM NEW.vulnerability_id
       OR OLD.cvss_score IS DISTINCT FROM NEW.cvss_score
       OR OLD.is_internet_accessible IS DISTINCT FROM NEW.is_internet_accessible
       OR OLD.is_network_accessible IS DISTINCT FROM NEW.is_network_accessible
       OR OLD.exposure_vector IS DISTINCT FROM NEW.exposure_vector
       OR OLD.data_exposure_risk IS DISTINCT FROM NEW.data_exposure_risk
       OR OLD.compliance_impact IS DISTINCT FROM NEW.compliance_impact
       OR OLD.validation_outcome IS DISTINCT FROM NEW.validation_outcome)
    EXECUTE FUNCTION finding_priority_enqueue_finding_update();
