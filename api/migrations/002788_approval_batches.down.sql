DROP INDEX IF EXISTS idx_finding_status_approvals_batch;
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS fk_finding_status_approvals_batch;
ALTER TABLE finding_status_approvals DROP COLUMN IF EXISTS batch_id;
DELETE FROM approval_signoffs WHERE subject_type = 'approval_batch';
DROP TABLE IF EXISTS approval_batches;
