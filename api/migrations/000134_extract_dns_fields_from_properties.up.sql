-- =============================================================================
-- Migration 000134: Extract DNS fields from nested properties to flat fields
-- =============================================================================
-- Collector stores DNS data as:
--   domain:    {"domain": {"dns_records": [{"ttl":300,"name":"x","type":"A","value":"1.2.3.4"}]}, "collector_type":"gcp-dns", "collector_source":"vndirect-compute"}
--   subdomain: {"domain": {"dns_records": [...]}, "root_domain":"parent.com", "collector_type":"gcp-dns", ...}
--
-- UI reads flat fields: record_type, provider, registrar, nameserver, ip_address
-- This migration extracts from nested JSONB → flat top-level properties keys.
-- =============================================================================

-- Step 1: Extract first DNS record type → record_type (e.g., "A", "CNAME", "AAAA", "MX")
UPDATE assets SET properties = properties || jsonb_build_object(
  'record_type', (properties->'domain'->'dns_records'->0->>'type')
)
WHERE (asset_type = 'domain' OR asset_type = 'subdomain')
  AND properties->'domain'->'dns_records' IS NOT NULL
  AND jsonb_array_length(properties->'domain'->'dns_records') > 0
  AND (properties->>'record_type' IS NULL OR properties->>'record_type' = '');

-- Step 2: Extract resolved IP from A/AAAA records → resolved_ip
UPDATE assets SET properties = properties || jsonb_build_object(
  'resolved_ip', (properties->'domain'->'dns_records'->0->>'value')
)
WHERE (asset_type = 'domain' OR asset_type = 'subdomain')
  AND properties->'domain'->'dns_records' IS NOT NULL
  AND jsonb_array_length(properties->'domain'->'dns_records') > 0
  AND (properties->'domain'->'dns_records'->0->>'type') IN ('A', 'AAAA')
  AND (properties->>'resolved_ip' IS NULL OR properties->>'resolved_ip' = '');

-- Step 3: Extract CNAME target → cname_target
UPDATE assets SET properties = properties || jsonb_build_object(
  'cname_target', (properties->'domain'->'dns_records'->0->>'value')
)
WHERE (asset_type = 'domain' OR asset_type = 'subdomain')
  AND properties->'domain'->'dns_records' IS NOT NULL
  AND jsonb_array_length(properties->'domain'->'dns_records') > 0
  AND (properties->'domain'->'dns_records'->0->>'type') = 'CNAME'
  AND (properties->>'cname_target' IS NULL OR properties->>'cname_target' = '');

-- Step 4: Extract TTL → ttl
UPDATE assets SET properties = properties || jsonb_build_object(
  'ttl', (properties->'domain'->'dns_records'->0->'ttl')
)
WHERE (asset_type = 'domain' OR asset_type = 'subdomain')
  AND properties->'domain'->'dns_records' IS NOT NULL
  AND jsonb_array_length(properties->'domain'->'dns_records') > 0
  AND (properties->>'ttl' IS NULL);

-- Step 5: Extract all unique record types → dns_record_types (comma-separated)
UPDATE assets SET properties = properties || jsonb_build_object(
  'dns_record_types', (
    SELECT string_agg(DISTINCT rec->>'type', ', ' ORDER BY rec->>'type')
    FROM jsonb_array_elements(properties->'domain'->'dns_records') AS rec
  )
)
WHERE (asset_type = 'domain' OR asset_type = 'subdomain')
  AND properties->'domain'->'dns_records' IS NOT NULL
  AND jsonb_array_length(properties->'domain'->'dns_records') > 0
  AND (properties->>'dns_record_types' IS NULL OR properties->>'dns_record_types' = '');

-- Step 6: Extract all resolved IPs → resolved_ips (comma-separated, A/AAAA only)
UPDATE assets SET properties = properties || jsonb_build_object(
  'resolved_ips', (
    SELECT string_agg(DISTINCT rec->>'value', ', ')
    FROM jsonb_array_elements(properties->'domain'->'dns_records') AS rec
    WHERE rec->>'type' IN ('A', 'AAAA')
  )
)
WHERE (asset_type = 'domain' OR asset_type = 'subdomain')
  AND properties->'domain'->'dns_records' IS NOT NULL
  AND jsonb_array_length(properties->'domain'->'dns_records') > 0
  AND (properties->>'resolved_ips' IS NULL OR properties->>'resolved_ips' = '');

-- Step 7: Promote collector_type and collector_source to flat fields (already flat, just ensure present)
-- These are already at top level — no action needed.

-- Step 8: Promote root_domain for subdomains (strip trailing dot)
UPDATE assets SET properties = properties || jsonb_build_object(
  'root_domain', RTRIM(properties->>'root_domain', '.')
)
WHERE asset_type = 'subdomain'
  AND properties->>'root_domain' IS NOT NULL
  AND properties->>'root_domain' LIKE '%.';

-- Step 9: Extract dns_record_count
UPDATE assets SET properties = properties || jsonb_build_object(
  'dns_record_count', jsonb_array_length(properties->'domain'->'dns_records')
)
WHERE (asset_type = 'domain' OR asset_type = 'subdomain')
  AND properties->'domain'->'dns_records' IS NOT NULL
  AND (properties->>'dns_record_count' IS NULL);
