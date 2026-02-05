-- =============================================================================
-- Migration 042: SLA Policies & AI Triage Results
-- OpenCTEM OSS Edition
-- =============================================================================

-- =============================================================================
-- SLA Policies
-- =============================================================================

CREATE TABLE IF NOT EXISTS sla_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,

    -- Remediation deadlines by severity (in days)
    critical_days INTEGER NOT NULL DEFAULT 1,
    high_days INTEGER NOT NULL DEFAULT 7,
    medium_days INTEGER NOT NULL DEFAULT 30,
    low_days INTEGER NOT NULL DEFAULT 90,
    info_days INTEGER NOT NULL DEFAULT 365,

    -- Warning threshold
    warning_threshold_percent INTEGER NOT NULL DEFAULT 75,

    -- Escalation
    escalation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    escalation_config JSONB DEFAULT '{}',

    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE sla_policies IS 'SLA policies defining remediation deadlines by severity';
COMMENT ON COLUMN sla_policies.asset_id IS 'NULL = tenant-wide default policy, set = asset-specific override';
COMMENT ON COLUMN sla_policies.warning_threshold_percent IS 'Percentage of deadline elapsed before warning';

-- =============================================================================
-- AI Triage Results
-- =============================================================================

CREATE TABLE IF NOT EXISTS ai_triage_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,

    -- Request
    triage_type VARCHAR(50) NOT NULL,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error_message TEXT,

    -- LLM Details
    llm_provider VARCHAR(50),
    llm_model VARCHAR(100),
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,

    -- Assessment
    severity_assessment VARCHAR(20),
    severity_justification TEXT,
    risk_score DOUBLE PRECISION,
    exploitability VARCHAR(20),
    exploitability_details TEXT,
    business_impact TEXT,
    priority_rank INTEGER,
    remediation_steps JSONB DEFAULT '[]',
    false_positive_likelihood DOUBLE PRECISION,
    false_positive_reason TEXT,

    -- Related References
    related_cves TEXT[] DEFAULT '{}',
    related_cwes TEXT[] DEFAULT '{}',

    -- Raw Data
    raw_response JSONB DEFAULT '{}',
    analysis_summary TEXT,
    metadata JSONB DEFAULT '{}',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_triage_status CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
);

COMMENT ON TABLE ai_triage_results IS 'AI-powered vulnerability triage results with LLM analysis';
COMMENT ON COLUMN ai_triage_results.triage_type IS 'Type of triage analysis requested';
COMMENT ON COLUMN ai_triage_results.false_positive_likelihood IS 'Probability (0-1) that this is a false positive';

-- =============================================================================
-- Indexes
-- =============================================================================

-- SLA Policies
CREATE INDEX IF NOT EXISTS idx_sla_policies_tenant ON sla_policies(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sla_policies_asset ON sla_policies(asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sla_policies_default ON sla_policies(tenant_id, is_default) WHERE is_default = TRUE;
CREATE INDEX IF NOT EXISTS idx_sla_policies_active ON sla_policies(is_active) WHERE is_active = TRUE;

-- AI Triage Results
CREATE INDEX IF NOT EXISTS idx_ai_triage_tenant ON ai_triage_results(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ai_triage_finding ON ai_triage_results(finding_id);
CREATE INDEX IF NOT EXISTS idx_ai_triage_status ON ai_triage_results(status);
CREATE INDEX IF NOT EXISTS idx_ai_triage_pending ON ai_triage_results(tenant_id, status, requested_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_ai_triage_tenant_month ON ai_triage_results(tenant_id, created_at)
    WHERE status = 'completed';
CREATE INDEX IF NOT EXISTS idx_ai_triage_finding_latest ON ai_triage_results(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_triage_pending_processing ON ai_triage_results(tenant_id, finding_id, status)
    WHERE status IN ('pending', 'processing');

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_sla_policies_updated_at ON sla_policies;
CREATE TRIGGER trigger_sla_policies_updated_at
    BEFORE UPDATE ON sla_policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS trigger_ai_triage_updated_at ON ai_triage_results;
CREATE TRIGGER trigger_ai_triage_updated_at
    BEFORE UPDATE ON ai_triage_results
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
