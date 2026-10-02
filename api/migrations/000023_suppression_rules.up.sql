-- =============================================================================
-- Migration 023: Suppression Rules
-- OpenCTEM OSS Edition
-- =============================================================================
-- Platform-controlled false positive management.
-- Allows security teams to suppress findings without code changes.

CREATE TABLE IF NOT EXISTS suppression_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Matching criteria (all conditions must match for rule to apply)
    rule_id VARCHAR(500),
    tool_name VARCHAR(100),
    path_pattern VARCHAR(1000),
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,

    -- Suppression details
    name VARCHAR(255) NOT NULL,
    description TEXT,
    suppression_type VARCHAR(50) NOT NULL DEFAULT 'false_positive',

    -- Approval workflow
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    requested_by UUID NOT NULL REFERENCES users(id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    rejected_by UUID REFERENCES users(id),
    rejected_at TIMESTAMPTZ,
    rejection_reason TEXT,

    -- Expiration
    expires_at TIMESTAMPTZ,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_suppression_rules_type CHECK (suppression_type IN ('false_positive', 'accepted_risk', 'wont_fix')),
    CONSTRAINT chk_suppression_rules_status CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    CONSTRAINT chk_suppression_rules_at_least_one_criterion CHECK (
        rule_id IS NOT NULL OR
        path_pattern IS NOT NULL OR
        asset_id IS NOT NULL
    )
);

COMMENT ON TABLE suppression_rules IS 'Platform-controlled suppression rules for false positive management';
COMMENT ON COLUMN suppression_rules.rule_id IS 'Tool rule ID pattern, supports wildcards (e.g., "semgrep.*")';
COMMENT ON COLUMN suppression_rules.path_pattern IS 'File path glob pattern (e.g., "tests/**", "*.test.go")';
COMMENT ON COLUMN suppression_rules.suppression_type IS 'Type of suppression: false_positive, accepted_risk, wont_fix';

-- Track which findings were suppressed by which rules
CREATE TABLE IF NOT EXISTS finding_suppressions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    suppression_rule_id UUID NOT NULL REFERENCES suppression_rules(id) ON DELETE CASCADE,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    applied_by VARCHAR(50) NOT NULL DEFAULT 'system',

    CONSTRAINT finding_suppressions_unique UNIQUE (finding_id, suppression_rule_id)
);

COMMENT ON TABLE finding_suppressions IS 'Tracks which findings are suppressed by which rules';

-- Audit log for suppression rule changes
CREATE TABLE IF NOT EXISTS suppression_rule_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    suppression_rule_id UUID NOT NULL REFERENCES suppression_rules(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL,
    actor_id UUID REFERENCES users(id),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_suppression_rule_audit_action CHECK (action IN ('created', 'approved', 'rejected', 'expired', 'deleted', 'updated'))
);

COMMENT ON TABLE suppression_rule_audit IS 'Audit trail for suppression rule changes';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Suppression rules indexes
CREATE INDEX IF NOT EXISTS idx_suppression_rules_tenant ON suppression_rules(tenant_id);
CREATE INDEX IF NOT EXISTS idx_suppression_rules_status ON suppression_rules(status) WHERE status = 'approved';
CREATE INDEX IF NOT EXISTS idx_suppression_rules_tool ON suppression_rules(tool_name) WHERE tool_name IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_suppression_rules_asset ON suppression_rules(asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_suppression_rules_expires ON suppression_rules(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_suppression_rules_created_at ON suppression_rules(created_at DESC);

-- Finding suppressions indexes
CREATE INDEX IF NOT EXISTS idx_finding_suppressions_finding ON finding_suppressions(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_suppressions_rule ON finding_suppressions(suppression_rule_id);

-- Suppression rule audit indexes
CREATE INDEX IF NOT EXISTS idx_suppression_rule_audit_rule ON suppression_rule_audit(suppression_rule_id);
CREATE INDEX IF NOT EXISTS idx_suppression_rule_audit_created_at ON suppression_rule_audit(created_at DESC);

-- =============================================================================
-- Functions
-- =============================================================================

-- Function to auto-expire suppression rules
CREATE OR REPLACE FUNCTION expire_suppression_rules()
RETURNS void AS $$
BEGIN
    UPDATE suppression_rules
    SET status = 'expired', updated_at = NOW()
    WHERE status = 'approved'
      AND expires_at IS NOT NULL
      AND expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION expire_suppression_rules() IS 'Marks expired suppression rules as expired';

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_suppression_rules_updated_at ON suppression_rules;
CREATE TRIGGER trigger_suppression_rules_updated_at
    BEFORE UPDATE ON suppression_rules
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

