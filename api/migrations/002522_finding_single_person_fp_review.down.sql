DROP TRIGGER IF EXISTS trg_finding_evidence_single_person_fp_review ON finding_evidence;
DROP FUNCTION IF EXISTS trg_finding_evidence_single_person_fp_review();
DROP TRIGGER IF EXISTS trg_findings_single_person_fp_review ON findings;
DROP FUNCTION IF EXISTS trg_findings_single_person_fp_review();
DROP FUNCTION IF EXISTS flag_single_person_fp_review(uuid, uuid, text, jsonb);
DROP FUNCTION IF EXISTS finding_severity_rank(text);
DELETE FROM finding_decision_reviews WHERE reason IN ('material_change_single_person', 'second_look_sample');
ALTER TABLE finding_decision_reviews DROP CONSTRAINT IF EXISTS chk_finding_decision_reviews_reason;
ALTER TABLE finding_decision_reviews ADD CONSTRAINT chk_finding_decision_reviews_reason
    CHECK (reason IN ('taint_source_changed', 'ioc_match'));
