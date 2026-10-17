-- Validates chk_finding_decision_reviews_reason, re-added NOT VALID by
-- approval_material_change (SHARE UPDATE EXCLUSIVE: reads and writes go on).
ALTER TABLE finding_decision_reviews VALIDATE CONSTRAINT chk_finding_decision_reviews_reason;
