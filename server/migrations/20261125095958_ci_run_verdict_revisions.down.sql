DELETE FROM durable_jobs WHERE kind = 'ci_rejudge';
ALTER TABLE durable_jobs DROP CONSTRAINT IF EXISTS chk_durable_jobs_kind;
ALTER TABLE durable_jobs ADD CONSTRAINT chk_durable_jobs_kind
    CHECK (kind IN ('jira_status_sync', 'github_status_sync', 'invitation_email'));

DROP TABLE IF EXISTS ci_reopen_pauses;
ALTER TABLE tenants DROP COLUMN IF EXISTS ci_reopen_on_decision;

DROP TRIGGER IF EXISTS trigger_ci_run_verdicts_append_only ON ci_run_verdicts;
DROP FUNCTION IF EXISTS ci_run_verdicts_append_only();
DROP TABLE IF EXISTS ci_run_verdicts;

ALTER TABLE ci_runs DROP COLUMN IF EXISTS gate_job_retried_revision;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS verdict_revised_at;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS verdict_revision;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS gate_job_id;
ALTER TABLE ci_runs DROP COLUMN IF EXISTS policy_snapshot;
