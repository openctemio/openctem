ALTER TABLE finding_decision_reviews
    ADD CONSTRAINT finding_decision_reviews_finding_id_fkey
    FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE;
ALTER TABLE finding_decision_reviews DROP CONSTRAINT IF EXISTS fk_finding_decision_reviews_finding_tenant;
