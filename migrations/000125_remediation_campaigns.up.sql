-- Remediation campaigns: track "fix all Log4j" as one campaign with progress.
-- Links to findings via filter criteria, tracks lifecycle and risk reduction.

CREATE TABLE IF NOT EXISTS remediation_campaigns (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',
    status VARCHAR(20) NOT NULL DEFAULT 'draft',
    -- draft, active, paused, validating, completed, canceled
    priority VARCHAR(20) NOT NULL DEFAULT 'medium',
    -- critical, high, medium, low

    -- Finding filter: which findings belong to this campaign
    -- Stored as JSONB filter criteria (severity, cve_id, asset_ids, source, etc.)
    finding_filter JSONB DEFAULT '{}',
    finding_count INT DEFAULT 0,

    -- Progress tracking
    resolved_count INT DEFAULT 0,
    progress NUMERIC(5,2) DEFAULT 0,

    -- Risk tracking
    risk_score_before NUMERIC(5,2),
    risk_score_after NUMERIC(5,2),
    risk_reduction NUMERIC(5,2),

    -- Assignment
    assigned_to UUID,
    assigned_team UUID,

    -- Timeline
    start_date DATE,
    due_date DATE,
    completed_at TIMESTAMPTZ,

    -- Metadata
    tags TEXT[] DEFAULT '{}',
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_remediation_campaigns_tenant ON remediation_campaigns(tenant_id);
CREATE INDEX idx_remediation_campaigns_status ON remediation_campaigns(tenant_id, status);
CREATE INDEX idx_remediation_campaigns_priority ON remediation_campaigns(tenant_id, priority);
CREATE INDEX idx_remediation_campaigns_due ON remediation_campaigns(due_date) WHERE status IN ('active', 'validating');
