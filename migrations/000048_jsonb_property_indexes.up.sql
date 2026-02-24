-- =============================================================================
-- Migration 000048: JSONB Property Indexes for Recon Data
-- OpenCTEM OSS Edition
-- =============================================================================
-- Adds specialised GIN and BTREE indexes on JSONB property paths that the
-- recon views and API queries use frequently.  All indexes use
-- IF NOT EXISTS for idempotency.
--
-- NOTE: The general GIN index on properties (idx_assets_properties) already
-- exists from 000008.  These indexes target specific JSONB sub-paths with
-- partial-index filters for much better selectivity.
-- =============================================================================

-- =============================================================================
-- 1. GIN Indexes for Nested JSONB Arrays
-- =============================================================================

-- Domain / subdomain DNS record lookups
CREATE INDEX IF NOT EXISTS idx_assets_props_domain_dns
    ON assets USING GIN ((properties->'domain'->'dns_records') jsonb_path_ops)
    WHERE asset_type IN ('domain', 'subdomain')
      AND properties->'domain'->'dns_records' IS NOT NULL;

-- IP address port lookups
CREATE INDEX IF NOT EXISTS idx_assets_props_ip_ports
    ON assets USING GIN ((properties->'ip_address'->'ports') jsonb_path_ops)
    WHERE asset_type IN ('ip_address', 'host', 'server')
      AND properties->'ip_address'->'ports' IS NOT NULL;

-- Service technical details
CREATE INDEX IF NOT EXISTS idx_assets_props_service
    ON assets USING GIN ((properties->'service') jsonb_path_ops)
    WHERE asset_type IN ('service', 'http_service', 'web_application')
      AND properties->'service' IS NOT NULL;

-- Technology detection (default ops for @> containment queries)
CREATE INDEX IF NOT EXISTS idx_assets_props_technologies
    ON assets USING GIN ((properties->'technologies'))
    WHERE properties->'technologies' IS NOT NULL;

-- Certificate details
CREATE INDEX IF NOT EXISTS idx_assets_props_certificate
    ON assets USING GIN ((properties->'certificate') jsonb_path_ops)
    WHERE asset_type = 'certificate'
      AND properties->'certificate' IS NOT NULL;

-- =============================================================================
-- 2. Composite Indexes for Common Query Patterns
-- =============================================================================

-- Tenant + asset type + discovery source (dashboard / list queries)
CREATE INDEX IF NOT EXISTS idx_assets_tenant_type_discovery
    ON assets (tenant_id, asset_type, discovery_source)
    WHERE status != 'archived';

-- Assets ranked by open-port count (dashboard widget)
CREATE INDEX IF NOT EXISTS idx_assets_ip_port_count
    ON assets (
        tenant_id,
        (jsonb_array_length(COALESCE(properties->'ip_address'->'ports', '[]'::jsonb))) DESC
    )
    WHERE asset_type IN ('ip_address', 'host', 'server')
      AND status != 'archived';

-- =============================================================================
-- 3. Expression Indexes for Common Filters
-- =============================================================================

-- TLS-enabled services
CREATE INDEX IF NOT EXISTS idx_assets_service_tls
    ON assets (tenant_id)
    WHERE asset_type IN ('service', 'http_service', 'web_application')
      AND (properties->'service'->>'tls')::boolean = true
      AND status != 'archived';

-- HTTP status codes (httpx results)
CREATE INDEX IF NOT EXISTS idx_assets_http_status
    ON assets (tenant_id, (properties->>'status_code'))
    WHERE asset_type IN ('http_service', 'web_application')
      AND properties->>'status_code' IS NOT NULL
      AND status != 'archived';
