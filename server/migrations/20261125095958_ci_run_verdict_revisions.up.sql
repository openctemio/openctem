-- Verdict revisions of a CI run and re-judging on a decision
-- (docs/rfcs/RFC-077-ci-enforced-gate-and-pr-feedback.md, amendment "Verdict
-- revisions"). Additive: new columns with defaults, two new tables, and the
-- durable job kind that carries a re-judge.

-- What the run's verdict was computed with besides its findings and their
-- decisions (policy as applied, baseline comparison, the run's own failures),
-- so a re-judge reuses it and only the decisions differ. NULL for runs
-- judged before this migration and for the sweeper's "not judged" verdict:
-- such runs are never re-judged.
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS policy_snapshot jsonb;
-- The CI job that asked for the verdict, from the signed token it exchanged
-- (GitLab job id, GitHub check run id); '' when unknown.
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS gate_job_id varchar(64) NOT NULL DEFAULT '';
-- The revision ci_runs.verdict holds (0: judged before revisions existed,
-- read as revision 1).
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS verdict_revision integer NOT NULL DEFAULT 0;
-- When a decision last revised the verdict (NULL: never).
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS verdict_revised_at timestamptz;
-- The highest revision whose gate job the platform retried on GitLab, so a
-- revision retries its gate job at most once.
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS gate_job_retried_revision integer NOT NULL DEFAULT 0;

-- Every verdict of a run, in order. Revision 1 is the first verdict; a
-- re-judge after a decision appends the next one. Rows never change (trigger
-- below); they go with their run.
CREATE TABLE IF NOT EXISTS ci_run_verdicts (
    tenant_id    uuid        NOT NULL,
    run_id       uuid        NOT NULL,
    revision     integer     NOT NULL,
    verdict      varchar(10) NOT NULL,
    detail       jsonb       NOT NULL,
    -- evaluate: a CI job asked for the verdict; decision: a decision in the
    -- platform re-judged the stored run.
    cause        varchar(20) NOT NULL,
    -- The findings (or the suppression rule) whose decisions changed the
    -- verdict, and the people who made them.
    decision_ids uuid[]      NOT NULL DEFAULT '{}',
    actor_ids    uuid[]      NOT NULL DEFAULT '{}',
    -- A decision turned a failing verdict into a passing one (the circuit
    -- breaker counts these per person).
    reopened     boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_ci_run_verdicts PRIMARY KEY (tenant_id, run_id, revision),
    CONSTRAINT fk_ci_run_verdicts_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES ci_runs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_ci_run_verdicts_revision CHECK (revision >= 1),
    CONSTRAINT chk_ci_run_verdicts_verdict CHECK (verdict IN ('pass', 'fail')),
    CONSTRAINT chk_ci_run_verdicts_cause CHECK (cause IN ('evaluate', 'decision'))
);

-- Reopens by one person in the last hour (circuit breaker).
CREATE INDEX IF NOT EXISTS idx_ci_run_verdicts_reopened
    ON ci_run_verdicts (tenant_id, created_at) WHERE reopened;

COMMENT ON TABLE ci_run_verdicts IS
    'Verdict revisions of a CI run (RFC-077): revision 1 is the first verdict, later ones come from decisions made in the platform. Append-only.';

CREATE OR REPLACE FUNCTION ci_run_verdicts_append_only() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'a CI run verdict revision never changes (run %, revision %)', OLD.run_id, OLD.revision
        USING ERRCODE = 'check_violation';
END;
$$;

COMMENT ON FUNCTION ci_run_verdicts_append_only() IS
    'BEFORE UPDATE on ci_run_verdicts: a verdict revision, the first verdict included, is never rewritten.';

DROP TRIGGER IF EXISTS trigger_ci_run_verdicts_append_only ON ci_run_verdicts;
CREATE TRIGGER trigger_ci_run_verdicts_append_only
    BEFORE UPDATE ON ci_run_verdicts
    FOR EACH ROW EXECUTE FUNCTION ci_run_verdicts_append_only();

-- Whether a final decision in the platform re-judges the organization's
-- blocked merge requests (on by default).
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS ci_reopen_on_decision boolean NOT NULL DEFAULT true;

-- Circuit breaker: a person whose decisions reopened too many merge requests
-- in an hour; their decisions stop reopening until an owner resumes them.
CREATE TABLE IF NOT EXISTS ci_reopen_pauses (
    tenant_id  uuid        NOT NULL,
    user_id    uuid        NOT NULL,
    paused_at  timestamptz NOT NULL DEFAULT now(),
    reopens    integer     NOT NULL,
    CONSTRAINT pk_ci_reopen_pauses PRIMARY KEY (tenant_id, user_id),
    CONSTRAINT fk_ci_reopen_pauses_tenant FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
);

COMMENT ON TABLE ci_reopen_pauses IS
    'People whose decisions no longer reopen blocked merge requests (over the hourly limit); an owner resumes them.';

-- The durable job that re-judges after a decision.
ALTER TABLE durable_jobs DROP CONSTRAINT IF EXISTS chk_durable_jobs_kind;
ALTER TABLE durable_jobs ADD CONSTRAINT chk_durable_jobs_kind
    CHECK (kind IN ('jira_status_sync', 'github_status_sync', 'invitation_email', 'ci_rejudge'));
