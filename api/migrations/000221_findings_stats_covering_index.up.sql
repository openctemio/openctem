-- Covering index for the tenant-wide finding aggregates on the dashboard
-- path: GET /findings/stats (FindingRepository.GetStats) and the open-finding
-- aggregate of GET /dashboard/executive-summary. Both read only these columns
-- for one tenant, so they can be index-only scans instead of heap scans of
-- every (wide: snippet/description/metadata/stacks) finding row. asset_id is
-- included for the data-scope and asset filters of the stats query.
--
-- Measured on a 200k-finding tenant (after VACUUM; index-only scans depend on
-- the visibility map, so heavily-churned tables see less of the gain):
--   /findings/stats aggregate          145ms -> 45ms   (4k tenant 5.4 -> 2.6ms)
--   executive-summary main query       127ms -> 53ms   (after its rewrite)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_stats_cover
  ON findings (tenant_id)
  INCLUDE (severity, status, source, is_in_kev, epss_score, sla_status, asset_id, priority_class);
