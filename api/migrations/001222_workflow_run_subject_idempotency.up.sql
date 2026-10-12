-- Automation runs: one run per subject, at most once per event (research/61 P0-2).
--
-- subject_id: the finding or asset a run is about. A batch of new findings
-- now starts one run per finding; the subject lets the run history and the
-- per-subject cooldown find them.
-- idempotency_key: the same event (a finding created, a scan run settled, a
-- triage done) starts an automation at most once. Unique per automation.
--
-- Both columns are nullable and added without a default: no table rewrite,
-- existing rows keep NULL (live has 0 runs).

ALTER TABLE workflow_runs ADD COLUMN IF NOT EXISTS subject_id uuid;
ALTER TABLE workflow_runs ADD COLUMN IF NOT EXISTS idempotency_key varchar(200);

CREATE UNIQUE INDEX IF NOT EXISTS uq_workflow_runs_idempotency
    ON workflow_runs (workflow_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Quota windows (runs per automation and per tenant in the last hour) and
-- the per-subject lookups.
CREATE INDEX IF NOT EXISTS idx_workflow_runs_workflow_created
    ON workflow_runs (workflow_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_tenant_created
    ON workflow_runs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_subject
    ON workflow_runs (workflow_id, subject_id, created_at DESC)
    WHERE subject_id IS NOT NULL;

COMMENT ON COLUMN workflow_runs.subject_id IS 'Finding or asset the run is about (NULL when none)';
COMMENT ON COLUMN workflow_runs.idempotency_key IS 'Event identity: the same event starts an automation at most once';
