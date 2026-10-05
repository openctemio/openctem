-- RFC-048 findings filters (research 17): an index for a filterable field.
-- One statement per file: CREATE INDEX CONCURRENTLY cannot run in a
-- transaction, and it does not block writes on the live table.
-- network_port (the Tenable port pivot). Partial: most findings are not
-- port-specific. Migration 000377 deferred this index until a query used it.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_findings_tenant_network_port ON findings (tenant_id, network_port) WHERE network_port IS NOT NULL;
