-- Restores the two-origin CHECK without deleting anything: manual records
-- stay (NOT VALID), new ones are refused. The request/responses moved out of
-- findings.metadata are not put back in clear: that move is one-way by
-- design (no secret value is ever written back to the finding).
ALTER TABLE finding_evidence DROP CONSTRAINT IF EXISTS finding_evidence_origin_check;
ALTER TABLE finding_evidence ADD CONSTRAINT finding_evidence_origin_check
    CHECK (origin IN ('detection', 'retest')) NOT VALID;

COMMENT ON COLUMN finding_evidence.origin IS NULL;
