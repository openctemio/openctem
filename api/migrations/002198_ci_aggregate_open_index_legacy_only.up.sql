-- Concurrent jobs joining one pipeline run must all get the run (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md,
-- section 4.1). The insert of an aggregate run names idx_ci_runs_pipeline_run in ON CONFLICT, but the older
-- attempt-keyed idx_ci_runs_aggregate_open (open runs) matched the same new rows. When two jobs passed the
-- ON CONFLICT pre-check at once, the loser's entry in that second unique index raised a unique violation instead
-- of falling back to DO NOTHING, and its token exchange failed with no run.
--
-- The attempt-keyed index now covers only the runs opened before the pipeline-run key (evidence_union false); no
-- code inserts those any more. Index builds on ci_runs are short (the partial index covers open runs only).

DROP INDEX IF EXISTS idx_ci_runs_aggregate_open;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ci_runs_aggregate_open
    ON ci_runs (tenant_id, pipeline_id, external_run_id, run_attempt, commit_sha)
    WHERE aggregate AND status = 'running' AND NOT evidence_union;
