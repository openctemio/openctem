-- Approval and assignment rule indexes for query optimization
-- These indexes improve approval listing and assignment rule lookup performance.

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_approvals_finding_status
  ON finding_status_approvals(finding_id, status);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_approvals_tenant_status_created
  ON finding_status_approvals(tenant_id, status, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assignment_rules_tenant_active_priority
  ON assignment_rules(tenant_id, is_active, priority);
