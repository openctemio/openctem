-- Covering index for the tenant-wide finding rollups (dashboard stats,
-- executive summary, finding groups, attack-graph node counts). It widens
-- idx_findings_tenant_stats_cover with the columns those queries also read
-- (branch_only, created_at, resolved_at, cve_id, cvss_score,
-- vulnerability_id), so they run as index-only scans instead of reading the
-- wide findings rows. The old index is dropped by the next migration.
--
-- CONCURRENTLY keeps the table writable while it builds; it cannot run in a
-- transaction, so this file holds exactly one statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_rollup_cover
    ON findings (tenant_id)
    INCLUDE (severity, status, source, is_in_kev, epss_score, sla_status, asset_id, priority_class,
             branch_only, created_at, resolved_at, cve_id, cvss_score, vulnerability_id);
