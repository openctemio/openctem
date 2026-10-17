DROP INDEX IF EXISTS idx_finding_status_approvals_batch;
ALTER TABLE finding_status_approvals DROP CONSTRAINT IF EXISTS fk_finding_status_approvals_batch;
ALTER TABLE finding_status_approvals DROP COLUMN IF EXISTS batch_id;
-- approval_signoffs comes from an earlier migration; a rollback past it has
-- no table to clean.
DO $$
BEGIN
    IF to_regclass('public.approval_signoffs') IS NOT NULL THEN
        DELETE FROM approval_signoffs WHERE subject_type = 'approval_batch';
    END IF;
END $$;
DROP TABLE IF EXISTS approval_batches;
