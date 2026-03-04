-- Finding Status Approvals
-- Tracks approval workflow for protected status transitions (false_positive, accepted)

CREATE TABLE IF NOT EXISTS finding_status_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    requested_status TEXT NOT NULL,
    requested_by UUID NOT NULL REFERENCES users(id),
    justification TEXT,
    approved_by UUID REFERENCES users(id),
    approved_at TIMESTAMPTZ,
    rejected_by UUID REFERENCES users(id),
    rejected_at TIMESTAMPTZ,
    rejection_reason TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX idx_approvals_finding ON finding_status_approvals(finding_id);
CREATE INDEX idx_approvals_tenant_status ON finding_status_approvals(tenant_id, status);
CREATE INDEX idx_approvals_requested_by ON finding_status_approvals(requested_by);
