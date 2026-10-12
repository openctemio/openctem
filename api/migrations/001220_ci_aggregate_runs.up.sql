-- Aggregate CI runs (RFC-051): the parallel capability jobs of one pipeline
-- run report into ONE run, and one final job asks for the verdict on all of
-- them.
--
-- ci_runs.aggregate marks such a run. At most one aggregate run is open
-- (status running) per pipeline, external run id, attempt and commit: the
-- jobs that join find it through idx_ci_runs_aggregate_open, and two jobs
-- exchanging at the same moment cannot open two (the second insert
-- conflicts and joins).
--
-- ci_run_tokens holds one upload token hash per job of an aggregate run
-- (each job exchanges its own OIDC token, and a job's token must keep
-- working while another job joins). An aggregate run keeps no token in
-- ci_runs.token_hash. Rows are deleted with their run, and by the CI
-- retention job once expired; the token itself is never stored.
--
-- A defaulted column, a partial index over few rows and a new table: no
-- table rewrite, no backfill.

ALTER TABLE ci_runs
    ADD COLUMN IF NOT EXISTS aggregate boolean DEFAULT false NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_ci_runs_aggregate_open
    ON ci_runs (tenant_id, pipeline_id, external_run_id, run_attempt, commit_sha)
    WHERE aggregate AND status = 'running';

CREATE TABLE IF NOT EXISTS ci_run_tokens (
    token_hash bytea PRIMARY KEY,
    tenant_id uuid NOT NULL,
    run_id uuid NOT NULL,
    external_job_id character varying(64) DEFAULT ''::character varying NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT fk_ci_run_tokens_run FOREIGN KEY (tenant_id, run_id)
        REFERENCES ci_runs (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ci_run_tokens_run ON ci_run_tokens (tenant_id, run_id);
CREATE INDEX IF NOT EXISTS idx_ci_run_tokens_expires ON ci_run_tokens (tenant_id, expires_at);

COMMENT ON COLUMN ci_runs.aggregate IS 'The run is shared by every capability job of one pipeline run (RFC-051); its upload tokens are in ci_run_tokens.';
COMMENT ON TABLE ci_run_tokens IS 'Upload token hashes (SHA-256) of the jobs of an aggregate CI run, one per job exchange. The token itself is never stored. Deleted with the run, and by the CI retention job once expired.';
