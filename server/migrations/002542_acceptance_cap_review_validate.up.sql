-- Validates the widened decision review reason CHECK (acceptance_cap_review).
ALTER TABLE finding_decision_reviews VALIDATE CONSTRAINT chk_finding_decision_reviews_reason;
