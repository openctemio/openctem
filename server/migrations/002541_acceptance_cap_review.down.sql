DELETE FROM finding_decision_reviews WHERE reason = 'acceptance_exceeds_cap';
ALTER TABLE finding_decision_reviews DROP CONSTRAINT chk_finding_decision_reviews_reason;
ALTER TABLE finding_decision_reviews ADD CONSTRAINT chk_finding_decision_reviews_reason
    CHECK (reason IN ('taint_source_changed', 'ioc_match'));
DROP FUNCTION IF EXISTS finding_max_acceptance_days(text, boolean);
