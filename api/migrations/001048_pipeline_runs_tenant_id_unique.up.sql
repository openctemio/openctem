-- research/27 P0-3 (docs/architecture/scan-stages.md): the chaining tables
-- reference a run together with its tenant, so a row of tenant A can never
-- point at a run of tenant B. A composite foreign key needs a unique index on
-- pipeline_runs (tenant_id, id); id is the primary key, so it can never
-- conflict. Built CONCURRENTLY so run writes are not blocked; one statement
-- per file because CREATE INDEX CONCURRENTLY cannot run in a transaction.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_pipeline_runs_tenant_id_id ON pipeline_runs (tenant_id, id);
