-- Recorded request/responses become finding evidence
-- (docs/architecture/finding-evidence.md, "Recorded request/responses"): a
-- request/response a person records on a finding (a pentest write-up, an
-- import, a drafted finding) is stored like tool evidence, masked with its
-- secret values encrypted apart, under origin 'manual'. The entries still
-- kept in clear in findings.metadata.request_responses are moved by the API
-- at start-up (masking and encryption need the application key, so this
-- migration cannot do it); see evidence.Service.MoveLegacyRequestResponses.
--
-- Live impact: the CHECK is swapped NOT VALID, then validated (a scan of
-- finding_evidence under SHARE UPDATE EXCLUSIVE, no write lock held).

ALTER TABLE finding_evidence DROP CONSTRAINT IF EXISTS finding_evidence_origin_check;
ALTER TABLE finding_evidence ADD CONSTRAINT finding_evidence_origin_check
    CHECK (origin IN ('detection', 'retest', 'manual')) NOT VALID;
ALTER TABLE finding_evidence VALIDATE CONSTRAINT finding_evidence_origin_check;

COMMENT ON COLUMN finding_evidence.origin IS
    'detection (a scan report), retest (a retest attempt) or manual (a request/response a person recorded; kept as long as the finding).';
