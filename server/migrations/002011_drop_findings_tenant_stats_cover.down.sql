CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_stats_cover
    ON findings (tenant_id)
    INCLUDE (severity, status, source, is_in_kev, epss_score, sla_status, asset_id, priority_class);
