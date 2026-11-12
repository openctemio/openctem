-- A workflow scan whose targets fall in several scan zones runs as one child
-- run per zone under a parent run (docs/architecture/scan-zones.md, "Workflow
-- runs over several zones"). parent_run_id links a child to its parent; the
-- composite foreign key keeps both in the same tenant.
--
-- Live impact: one nullable column (no rewrite, no default), a foreign key
-- added NOT VALID then validated (no long write lock), one partial index
-- built on the rows that have a parent (none yet).

ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS parent_run_id UUID;

ALTER TABLE scan_runs
    ADD CONSTRAINT fk_scan_runs_parent_run
    FOREIGN KEY (tenant_id, parent_run_id) REFERENCES scan_runs (tenant_id, id) ON DELETE CASCADE NOT VALID;
-- Every existing row has no parent: validated without blocking writes.
ALTER TABLE scan_runs VALIDATE CONSTRAINT fk_scan_runs_parent_run;

CREATE INDEX IF NOT EXISTS idx_scan_runs_parent_run
    ON scan_runs (tenant_id, parent_run_id) WHERE parent_run_id IS NOT NULL;
