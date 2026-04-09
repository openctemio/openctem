-- =============================================================================
-- Migration 108: Index for relationship type aggregation queries
--
-- The /api/v1/relationships/usage-stats endpoint runs:
--
--     SELECT relationship_type, COUNT(*) AS n
--     FROM asset_relationships
--     WHERE tenant_id = $1
--     GROUP BY relationship_type
--
-- The existing UNIQUE constraint
-- (tenant_id, source_asset_id, target_asset_id, relationship_type)
-- covers the WHERE filter, but Postgres has to scan more pages than
-- necessary because the index is wider than what the GROUP BY needs.
--
-- A narrower (tenant_id, relationship_type) covering index lets the
-- planner do an Index Only Scan + HashAggregate, which is significantly
-- faster on tenants with hundreds of thousands of relationships.
--
-- Cost is small: ~16 bytes per row × N rows. Worth it for the read
-- performance and for any future telemetry / dashboards built on the
-- usage-stats endpoint.
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_asset_relationships_tenant_type
    ON asset_relationships (tenant_id, relationship_type);
