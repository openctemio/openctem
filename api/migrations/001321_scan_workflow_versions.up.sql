-- A run is pinned to the scan workflow it started with (research/62 P0-10).
-- When a run starts, the workflow's spec (settings and steps) is saved as a
-- version if it differs from the latest one; the run records that version and
-- reads its settings and steps from it until it ends, so an edit made while
-- it runs changes the next run, never this one. Versions are immutable and
-- kept as long as the workflow (its runs show what they ran).

CREATE TABLE IF NOT EXISTS scan_workflow_versions (
    tenant_id        UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    scan_workflow_id UUID NOT NULL REFERENCES scan_workflows (id) ON DELETE CASCADE,
    version          INTEGER NOT NULL CHECK (version >= 1),
    spec             JSONB NOT NULL CHECK (jsonb_typeof(spec) = 'object'),
    spec_digest      VARCHAR(64) NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scan_workflow_id, version)
);
CREATE INDEX IF NOT EXISTS idx_scan_workflow_versions_tenant ON scan_workflow_versions (tenant_id, scan_workflow_id);

ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS scan_workflow_version INTEGER;
ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS spec_digest VARCHAR(64);

COMMENT ON TABLE scan_workflow_versions IS 'Immutable spec (settings + steps) of a scan workflow as runs started with it; a run reads its pinned version.';
COMMENT ON COLUMN scan_runs.scan_workflow_version IS 'The scan_workflow_versions version this run executes (NULL: runs from before versions, or a run without a workflow).';
