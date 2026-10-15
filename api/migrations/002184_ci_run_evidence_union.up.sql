-- A pipeline run is the unit of CI evidence (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
-- section 4.1): every job, retry and re-run attempt of one pipeline run (pipeline, external run id,
-- commit) reports into ONE aggregate run, whatever its attempt and status. A re-run of only the gate
-- job used to open a new, empty run that judged nothing and passed; it now re-opens the run that
-- holds the earlier attempts' reports.
--
--   evidence_union         the run is keyed without the attempt (rows from before this migration
--                          keep the old key and are left as they are);
--   failed_capabilities          capabilities the last verdict found failed (the job's capability
--                                states, and those carried from earlier attempts);
--   carried_failed_capabilities  set when a later attempt re-opens the run: each keeps failing it
--                                until a report of THAT capability arrives;
--   carried_scan_failures        a runner that reports only a count of failed scanners (no capability
--                                states): the count keeps failing the run until a later upload.
--
-- New columns have constant defaults (no table rewrite); the unique index covers new rows only.

ALTER TABLE ci_runs
    ADD COLUMN IF NOT EXISTS evidence_union BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS carried_scan_failures INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS failed_capabilities TEXT[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN IF NOT EXISTS carried_failed_capabilities TEXT[] NOT NULL DEFAULT '{}'::text[];

CREATE UNIQUE INDEX IF NOT EXISTS idx_ci_runs_pipeline_run
    ON ci_runs (tenant_id, pipeline_id, external_run_id, commit_sha)
    WHERE aggregate AND evidence_union;

COMMENT ON COLUMN ci_runs.evidence_union IS 'Aggregate run keyed by pipeline run without the attempt: retries and re-runs add to it.';
COMMENT ON COLUMN ci_runs.carried_scan_failures IS 'Scanner failures of the verdict before a re-open; cleared by the next uploaded report.';
