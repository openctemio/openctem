-- CI trust for more OIDC issuers: Azure Pipelines, Bitbucket Pipelines,
-- CircleCI and Jenkins (OpenID Connect provider plugin), next to GitHub
-- Actions and GitLab CI. Design: docs/rfcs/RFC-051-ci-runner-identity-and-gate.md.
--
-- ci_runs.commit_verified: false when the provider's token carries no commit
-- (CircleCI, and Jenkins without a commit claim) and the run's commit is the
-- one the job reported. Such a commit is shown and audited but never matches
-- a break-glass override, which is granted per commit.
--
-- ci_trust_configs and ci_pipelines hold tens of rows per tenant: the
-- constraint swaps are short. The new ci_runs column has a constant default
-- (no table rewrite on PostgreSQL 11+).
ALTER TABLE ci_trust_configs DROP CONSTRAINT chk_ci_trust_configs_provider;
ALTER TABLE ci_trust_configs ADD CONSTRAINT chk_ci_trust_configs_provider
    CHECK (provider IN ('github', 'gitlab', 'azure_devops', 'bitbucket', 'circleci', 'jenkins'));

ALTER TABLE ci_pipelines DROP CONSTRAINT chk_ci_pipelines_provider;
ALTER TABLE ci_pipelines ADD CONSTRAINT chk_ci_pipelines_provider
    CHECK (provider IN ('github', 'gitlab', 'azure_devops', 'bitbucket', 'circleci', 'jenkins'));

ALTER TABLE ci_runs ADD COLUMN commit_verified BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN ci_runs.commit_verified IS
    'false: the provider''s token carries no commit and commit_sha is the one the job reported; it never matches a break-glass override.';
