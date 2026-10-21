-- The escalation job reads open findings whose deadline passed and whose
-- breach is not announced yet: only newly due rows match.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_sla_breach_due ON findings (sla_deadline) WHERE sla_breach_notified_at IS NULL AND sla_deadline IS NOT NULL AND NOT branch_only AND status IN ('confirmed', 'fix_applied', 'in_progress', 'new');
