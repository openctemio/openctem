-- Migration 000141: Promote sub_type from properties to column
--
-- Collectors send sub_type in properties JSONB. Ingest now promotes it,
-- but existing data needs backfill.
--
-- Two sources:
-- 1. properties->>'sub_type' (explicit)
-- 2. TypeAliases inference from asset_type (e.g., kubernetes assets with
--    properties containing namespace → sub_type = 'namespace')

-- ============================================================
-- Step 1: Promote explicit sub_type from properties
-- ============================================================
UPDATE assets
SET sub_type = properties->>'sub_type',
    properties = properties - 'sub_type',
    updated_at = NOW()
WHERE (sub_type IS NULL OR sub_type = '')
  AND properties->>'sub_type' IS NOT NULL
  AND properties->>'sub_type' != '';

-- ============================================================
-- Step 2: Infer sub_type from TypeAliases patterns
-- ============================================================

-- Kubernetes: cluster vs namespace
UPDATE assets SET sub_type = 'namespace', updated_at = NOW()
WHERE asset_type = 'kubernetes'
  AND (sub_type IS NULL OR sub_type = '')
  AND (name LIKE '%/%' OR properties->>'namespace' IS NOT NULL);

UPDATE assets SET sub_type = 'cluster', updated_at = NOW()
WHERE asset_type = 'kubernetes'
  AND (sub_type IS NULL OR sub_type = '')
  AND name NOT LIKE '%/%';

-- Network: infer from properties.type
UPDATE assets SET sub_type = properties->>'type', updated_at = NOW()
WHERE asset_type = 'network'
  AND (sub_type IS NULL OR sub_type = '')
  AND properties->>'type' IS NOT NULL
  AND properties->>'type' IN ('firewall', 'load_balancer', 'switch', 'router',
      'vpn_gateway', 'wireless_controller', 'ids', 'vpc', 'subnet');

-- Database: infer from properties.engine
UPDATE assets SET sub_type = properties->>'engine', updated_at = NOW()
WHERE asset_type = 'database'
  AND (sub_type IS NULL OR sub_type = '')
  AND properties->>'engine' IS NOT NULL;

-- Storage: infer s3_bucket from properties.type
UPDATE assets SET sub_type = 's3_bucket', updated_at = NOW()
WHERE asset_type = 'storage'
  AND (sub_type IS NULL OR sub_type = '')
  AND (properties->>'type' = 's3' OR name LIKE 's3://%');

-- Container: infer from registry
UPDATE assets SET sub_type = 'image', updated_at = NOW()
WHERE asset_type = 'container'
  AND (sub_type IS NULL OR sub_type = '');

-- Identity: infer from properties.type
UPDATE assets SET sub_type = properties->>'type', updated_at = NOW()
WHERE asset_type = 'identity'
  AND (sub_type IS NULL OR sub_type = '')
  AND properties->>'type' IS NOT NULL
  AND properties->>'type' IN ('iam_user', 'iam_role', 'service_account');

-- Service: infer from port/protocol
UPDATE assets SET sub_type = 'open_port', updated_at = NOW()
WHERE asset_type = 'service'
  AND (sub_type IS NULL OR sub_type = '')
  AND name ~ ':\d+:(tcp|udp)$';

-- Application: infer from properties or URL pattern
UPDATE assets SET sub_type = 'api', updated_at = NOW()
WHERE asset_type = 'application'
  AND (sub_type IS NULL OR sub_type = '')
  AND (name LIKE '%/api%' OR name LIKE '%api.%' OR properties->>'type' = 'api');

UPDATE assets SET sub_type = 'website', updated_at = NOW()
WHERE asset_type = 'application'
  AND (sub_type IS NULL OR sub_type = '')
  AND name LIKE 'https://%';

-- Cloud Account: infer provider as sub_type
UPDATE assets SET sub_type = properties->>'provider', updated_at = NOW()
WHERE asset_type = 'cloud_account'
  AND (sub_type IS NULL OR sub_type = '')
  AND properties->>'provider' IS NOT NULL;
