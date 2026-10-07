DROP INDEX IF EXISTS idx_workflow_runs_subject;
DROP INDEX IF EXISTS idx_workflow_runs_tenant_created;
DROP INDEX IF EXISTS idx_workflow_runs_workflow_created;
DROP INDEX IF EXISTS uq_workflow_runs_idempotency;
ALTER TABLE workflow_runs DROP COLUMN IF EXISTS idempotency_key;
ALTER TABLE workflow_runs DROP COLUMN IF EXISTS subject_id;
