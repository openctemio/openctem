-- Trust configurations and pipelines of the added providers cannot exist
-- under the old constraint: they are removed. Runs of a removed pipeline go
-- with it (the existing cascade); runs keep their history otherwise.
ALTER TABLE ci_runs DROP COLUMN commit_verified;

DELETE FROM ci_pipelines WHERE provider NOT IN ('github', 'gitlab');
DELETE FROM ci_trust_configs WHERE provider NOT IN ('github', 'gitlab');

ALTER TABLE ci_pipelines DROP CONSTRAINT chk_ci_pipelines_provider;
ALTER TABLE ci_pipelines ADD CONSTRAINT chk_ci_pipelines_provider
    CHECK (provider IN ('github', 'gitlab'));

ALTER TABLE ci_trust_configs DROP CONSTRAINT chk_ci_trust_configs_provider;
ALTER TABLE ci_trust_configs ADD CONSTRAINT chk_ci_trust_configs_provider
    CHECK (provider IN ('github', 'gitlab'));
