-- =============================================================================
-- Migration 000047: Recon Summary Views
-- OpenCTEM OSS Edition
-- =============================================================================
-- Creates read-only summary views for recon asset data:
--   - v_assets_domain_summary  (domain/subdomain assets with DNS info)
--   - v_assets_ip_summary      (IP/host/server assets with port/ASN info)
--   - v_assets_http_services   (HTTP services with technology detection)
-- =============================================================================

-- =============================================================================
-- 1. Domain Summary View
-- =============================================================================
-- Provides a flat view of domain/subdomain assets with DNS record and
-- nameserver counts extracted from the JSONB properties column.
-- =============================================================================

CREATE OR REPLACE VIEW v_assets_domain_summary AS
SELECT
    a.id,
    a.tenant_id,
    a.name,
    a.criticality,
    a.status,
    a.discovery_tool,
    a.discovered_at,
    a.first_seen,
    a.last_seen,
    jsonb_array_length(COALESCE(a.properties->'domain'->'dns_records', '[]'::jsonb)) AS dns_record_count,
    jsonb_array_length(COALESCE(a.properties->'domain'->'nameservers', '[]'::jsonb)) AS nameserver_count,
    a.properties->'domain'->>'registrar'  AS registrar,
    a.properties->'domain'->>'expires_at' AS expires_at
FROM assets a
WHERE a.asset_type IN ('domain', 'subdomain');

COMMENT ON VIEW v_assets_domain_summary IS 'Summary view of domain/subdomain assets with DNS metadata from properties';

-- =============================================================================
-- 2. IP Address Summary View
-- =============================================================================
-- Provides a flat view of IP-related assets with open port counts and
-- geolocation/ASN data extracted from the JSONB properties column.
-- =============================================================================

CREATE OR REPLACE VIEW v_assets_ip_summary AS
SELECT
    a.id,
    a.tenant_id,
    a.name,
    a.criticality,
    a.status,
    a.discovery_tool,
    a.discovered_at,
    a.first_seen,
    a.last_seen,
    jsonb_array_length(COALESCE(a.properties->'ip_address'->'ports', '[]'::jsonb)) AS open_port_count,
    a.properties->'ip_address'->>'version'  AS ip_version,
    a.properties->'ip_address'->>'hostname' AS hostname,
    a.properties->'ip_address'->>'asn'      AS asn,
    a.properties->'ip_address'->>'asn_org'  AS asn_org,
    a.properties->'ip_address'->>'country'  AS country
FROM assets a
WHERE a.asset_type IN ('ip_address', 'host', 'server');

COMMENT ON VIEW v_assets_ip_summary IS 'Summary view of IP/host/server assets with port counts and ASN info from properties';

-- =============================================================================
-- 3. HTTP Services Summary View
-- =============================================================================
-- Provides a flat view of HTTP service assets with service details and
-- technology detection data extracted from the JSONB properties column.
-- =============================================================================

CREATE OR REPLACE VIEW v_assets_http_services AS
SELECT
    a.id,
    a.tenant_id,
    a.name,
    a.criticality,
    a.status,
    a.discovery_tool,
    a.discovered_at,
    a.first_seen,
    a.last_seen,
    a.properties->'service'->>'name'          AS service_name,
    a.properties->'service'->>'version'       AS service_version,
    (a.properties->'service'->>'port')::int   AS port,
    a.properties->'service'->>'protocol'      AS protocol,
    (a.properties->'service'->>'tls')::boolean AS tls_enabled,
    a.properties->>'status_code'              AS status_code,
    a.properties->>'title'                    AS title,
    a.properties->'technologies'              AS technologies
FROM assets a
WHERE a.asset_type IN ('service', 'http_service', 'web_application');

COMMENT ON VIEW v_assets_http_services IS 'Summary view of HTTP services with technology detection from properties';
