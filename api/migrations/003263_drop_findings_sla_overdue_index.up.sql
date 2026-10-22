-- idx_findings_sla_overdue filters on retired values (breached, closed,
-- verified), so no query can use it; idx_findings_sla_breach_due replaces it.
DROP INDEX CONCURRENTLY IF EXISTS idx_findings_sla_overdue;
