-- Remediation groups (RFC-015): a finding's "fix identity" — the stable key of
-- the patch/upgrade that resolves it. Findings sharing a key form a group that
-- can be resolved in one action ("one patch fixes the whole family").
--
-- Kept in a feature-owned side-table (not a column on the central findings
-- table) so the grouping concern stays out of the core finding read/write path
-- and the feature can be dropped without touching core. One row per finding,
-- CASCADE-deleted with the finding; re-derived idempotently at each ingest.
CREATE TABLE IF NOT EXISTS finding_remediation_keys (
    finding_id      UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    remediation_key TEXT NOT NULL,
    -- Human-readable title of the fix action (e.g. the Nessus solution or the
    -- "upgrade <component>" line), shown in the group list without re-deriving.
    title           TEXT NOT NULL DEFAULT '',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Group listing + resolve both scan by (tenant, key); the join back to findings
-- filters by status/source.
CREATE INDEX IF NOT EXISTS idx_finding_remediation_keys_tenant_key
    ON finding_remediation_keys (tenant_id, remediation_key);
