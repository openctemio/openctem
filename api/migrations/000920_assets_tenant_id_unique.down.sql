-- Drops the referenced key of the composite tenant foreign keys (000921 down
-- removes those first).
DROP INDEX CONCURRENTLY IF EXISTS uq_assets_tenant_id_id;
