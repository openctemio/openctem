-- =============================================================================
-- Migration 000048 DOWN: Drop JSONB Property Indexes
-- =============================================================================

DROP INDEX IF EXISTS idx_assets_http_status;
DROP INDEX IF EXISTS idx_assets_service_tls;
DROP INDEX IF EXISTS idx_assets_ip_port_count;
DROP INDEX IF EXISTS idx_assets_tenant_type_discovery;
DROP INDEX IF EXISTS idx_assets_props_certificate;
DROP INDEX IF EXISTS idx_assets_props_technologies;
DROP INDEX IF EXISTS idx_assets_props_service;
DROP INDEX IF EXISTS idx_assets_props_ip_ports;
DROP INDEX IF EXISTS idx_assets_props_domain_dns;
