-- CI runs record the CI job that exchanged the token (GitHub check_run_id,
-- GitLab job_id), from the verified OIDC claims; a run token is renewed only
-- for that job (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md).
-- Metadata only: adding a column with a constant default rewrites nothing.
ALTER TABLE ci_runs ADD COLUMN IF NOT EXISTS external_job_id VARCHAR(64) NOT NULL DEFAULT '';
