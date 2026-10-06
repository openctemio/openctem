-- Validate the composite trust-configuration foreign keys 001113 added NOT
-- VALID. VALIDATE takes a lock that does not block reads or writes, in its own
-- transaction (separate migration file).
ALTER TABLE ci_runs VALIDATE CONSTRAINT fk_ci_runs_trust_config;
ALTER TABLE ci_pipelines VALIDATE CONSTRAINT fk_ci_pipelines_trust_config;
