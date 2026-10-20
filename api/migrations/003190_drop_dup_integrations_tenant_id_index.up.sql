-- idx_integrations_tenant_id_pk (tenant_id, id) duplicates uq_integrations_tenant_id.
DROP INDEX CONCURRENTLY IF EXISTS idx_integrations_tenant_id_pk;
