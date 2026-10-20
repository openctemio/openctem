-- Removes asset risk change requests and their sign-offs. A change a request
-- was waiting for is not applied; the asset keeps the values it has.
DELETE FROM approval_signoffs WHERE subject_type = 'asset_risk_request';
ALTER TABLE approval_signoffs DROP CONSTRAINT IF EXISTS chk_approval_signoffs_subject_type;
ALTER TABLE approval_signoffs ADD CONSTRAINT chk_approval_signoffs_subject_type
    CHECK (subject_type IN ('finding_approval', 'approval_batch', 'suppression_rule', 'severity_request'));
DROP TABLE IF EXISTS asset_risk_requests;
