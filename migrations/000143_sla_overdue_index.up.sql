-- Migration 000143: Index for SLA overdue finding queries (RFC-005 Gap 7)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_sla_overdue
  ON findings(tenant_id, sla_deadline)
  WHERE sla_status NOT IN ('breached','not_applicable')
    AND status NOT IN ('closed','resolved','false_positive','verified');
