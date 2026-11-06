DROP TRIGGER IF EXISTS trg_findings_sub_status_settle ON findings;
DROP FUNCTION IF EXISTS findings_settle_sub_status();
ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_sub_status;
