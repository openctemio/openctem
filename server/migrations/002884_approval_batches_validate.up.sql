-- Validates fk_finding_status_approvals_batch, added NOT VALID by
-- approval_batches (SHARE ROW EXCLUSIVE on the referencing table only for the
-- check; the table is small).
ALTER TABLE finding_status_approvals VALIDATE CONSTRAINT fk_finding_status_approvals_batch;
