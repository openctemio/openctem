-- A review flag names its finding together with the finding's tenant, so a
-- flag can never pair one tenant with another tenant's finding. Added NOT
-- VALID (no scan under lock); migration 002208 validates it.
ALTER TABLE finding_decision_reviews
    ADD CONSTRAINT fk_finding_decision_reviews_finding_tenant
    FOREIGN KEY (finding_id, tenant_id) REFERENCES findings (id, tenant_id) ON DELETE CASCADE NOT VALID;
ALTER TABLE finding_decision_reviews DROP CONSTRAINT IF EXISTS finding_decision_reviews_finding_id_fkey;
