-- Validation evidence (CTEM Stage-4 "Validation").
--
-- Persists proof-of-fix / validation results: an agent (or a pentest retest)
-- executes a technique against a finding's target and POSTs the resulting
-- Evidence back. Each row links to the finding it validated; the full Evidence
-- envelope is stored as JSONB after secret redaction, with the key fields
-- denormalised into columns for filtering and chronological reads.
CREATE TABLE IF NOT EXISTS validation_evidence (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id        UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    simulation_run_id UUID,
    executor_kind     VARCHAR(40) NOT NULL,
    technique         VARCHAR(40),
    outcome           VARCHAR(20) NOT NULL,
    summary           TEXT,
    evidence          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_validation_evidence_outcome CHECK (outcome IN (
        'detected', 'not_detected', 'inconclusive', 'error', 'skipped'
    ))
);

-- List-by-finding (UI finding detail) + tenant-scoped chronological feed.
CREATE INDEX IF NOT EXISTS idx_validation_evidence_finding
    ON validation_evidence (tenant_id, finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_validation_evidence_tenant_created
    ON validation_evidence (tenant_id, created_at DESC);
