-- Covering index for GET /findings/stats (FindingRepository.GetStats): the
-- single aggregate reads only these columns for one tenant, so it can be an
-- index-only scan instead of a heap scan of every finding row (findings rows
-- are wide: snippet/description/metadata/stacks). asset_id is included for
-- the data-scope and asset filters of the same query.
--
-- Measured on a 200k-finding tenant: 145ms -> 45ms; 4k-finding tenant:
-- 5.4ms -> 2.6ms (after VACUUM; index-only scans depend on the visibility
-- map, so heavily-churned tables see less of the gain).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_stats_cover
  ON findings (tenant_id)
  INCLUDE (severity, status, source, is_in_kev, epss_score, sla_status, asset_id);
