-- Validates the widened review-reason check of the previous migration
-- (finding_single_person_fp_review), separately so the constraint swap does
-- not scan the table while it holds its lock.
ALTER TABLE finding_decision_reviews VALIDATE CONSTRAINT chk_finding_decision_reviews_reason;
