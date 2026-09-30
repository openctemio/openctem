-- Serves the findings list default sort (CTEM priority, then severity rank,
-- then newest) so a page is an index walk + LIMIT instead of reading and
-- top-N sorting every finding of the tenant. The expression must match the
-- ORDER BY emitted for sort=priority_class,severity,-created_at exactly
-- (FindingAllowedSortFields "severity" CASE and DefaultFindingSort).
--
-- Measured on a 200k-finding tenant (396k findings total), page 1 of 20:
-- 612ms (seq scan + sort) -> 0.14ms (index scan).
--
-- One statement per file: CREATE INDEX CONCURRENTLY cannot run inside the
-- implicit transaction of a multi-statement migration.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_priority_sort
  ON findings (
    tenant_id,
    priority_class,
    (CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END),
    created_at DESC
  );
