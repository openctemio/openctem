-- Migration 000146: Compensating Controls (RFC-005 Gap 6)
--
-- Security controls that mitigate risk without fixing the underlying vulnerability.
-- Links to assets/findings and provides a reduction_factor for risk scoring.

CREATE TABLE IF NOT EXISTS compensating_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    control_type VARCHAR(30) NOT NULL
      CHECK (control_type IN ('segmentation','identity','runtime','detection','other')),
    status VARCHAR(20) NOT NULL DEFAULT 'active'
      CHECK (status IN ('active','inactive','expired','untested')),
    reduction_factor DECIMAL(3,2) DEFAULT 0.0
      CHECK (reduction_factor >= 0 AND reduction_factor <= 1),
    last_tested_at TIMESTAMPTZ,
    test_result VARCHAR(20)
      CHECK (test_result IS NULL OR test_result IN ('pass','fail','partial')),
    test_evidence TEXT,
    expires_at TIMESTAMPTZ,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_comp_controls_tenant
  ON compensating_controls(tenant_id);
CREATE INDEX IF NOT EXISTS idx_comp_controls_active
  ON compensating_controls(tenant_id) WHERE status = 'active';

-- Link tables
CREATE TABLE IF NOT EXISTS compensating_control_assets (
    control_id UUID NOT NULL REFERENCES compensating_controls(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (control_id, asset_id)
);

CREATE TABLE IF NOT EXISTS compensating_control_findings (
    control_id UUID NOT NULL REFERENCES compensating_controls(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (control_id, finding_id)
);
