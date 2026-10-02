-- Migration 000144: Finding Verification Checklists (RFC-005 Gap 8)
--
-- Structured closure criteria: exposure cleared, evidence attached,
-- register updated, monitoring added, regression scheduled.

CREATE TABLE IF NOT EXISTS finding_verification_checklists (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Required items (must all be true to verify)
    exposure_cleared BOOLEAN NOT NULL DEFAULT false,
    evidence_attached BOOLEAN NOT NULL DEFAULT false,
    register_updated BOOLEAN NOT NULL DEFAULT false,

    -- Optional items (NULL = N/A, not required)
    monitoring_added BOOLEAN,
    regression_scheduled BOOLEAN,

    notes TEXT,
    completed_by UUID,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_verification_checklist_tenant
  ON finding_verification_checklists(tenant_id);
CREATE INDEX IF NOT EXISTS idx_verification_checklist_finding
  ON finding_verification_checklists(finding_id);
