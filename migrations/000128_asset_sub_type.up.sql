-- Add sub_type column to assets for type consolidation.
-- sub_type provides granularity within a core type:
--   type=network, sub_type=firewall
--   type=host,    sub_type=compute
--   type=identity, sub_type=iam_user
--
-- Backward compatible: sub_type is nullable. Old code ignores it.
-- Rollback: DROP COLUMN sub_type (no data loss, type column unchanged)

-- =============================================================================
-- Step 0: Fix asset_type_categories (sync with code-level categories)
-- =============================================================================

-- Add missing categories
INSERT INTO asset_type_categories (code, name, description, icon, display_order)
VALUES
    ('external_surface', 'External Surface', 'Internet-facing assets discovered from external perspective', 'globe', 1),
    ('network', 'Network & Security', 'Network devices and security appliances', 'shield', 5)
ON CONFLICT (code) DO NOTHING;

-- Fix category assignments
UPDATE asset_types SET category_id = (SELECT id FROM asset_type_categories WHERE code = 'external_surface')
    WHERE code IN ('domain', 'subdomain', 'ip_address', 'ip', 'ip_range', 'certificate', 'ssl_certificate');

UPDATE asset_types SET category_id = (SELECT id FROM asset_type_categories WHERE code = 'network')
    WHERE code IN ('network', 'firewall', 'load_balancer', 'port');

UPDATE asset_types SET category_id = (SELECT id FROM asset_type_categories WHERE code = 'infrastructure')
    WHERE code IN ('host', 'container', 'compute', 'serverless', 'server');

UPDATE asset_types SET category_id = (SELECT id FROM asset_type_categories WHERE code = 'identity')
    WHERE code IN ('user_account', 'credential', 'iam_user', 'iam_role', 'service_account');

-- =============================================================================
-- Step 1: Update CHECK constraint to allow new consolidated types
-- =============================================================================

-- Drop old constraint that doesn't include new types
ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_type;

-- Add new constraint with all types (core + legacy for backward compat)
ALTER TABLE assets ADD CONSTRAINT chk_assets_type CHECK (
    asset_type IN (
        -- Core types (15)
        'domain', 'subdomain', 'certificate', 'ip_address',
        'application', 'host', 'container', 'kubernetes',
        'network', 'service', 'cloud_account', 'storage',
        'database', 'repository', 'identity', 'unclassified',
        -- Legacy types (still accepted for backward compat)
        'website', 'web_application', 'api', 'mobile_app',
        'compute', 'serverless', 'vpc', 'subnet',
        'firewall', 'load_balancer',
        'kubernetes_cluster', 'kubernetes_namespace',
        'iam_user', 'iam_role', 'service_account',
        'data_store', 's3_bucket', 'container_registry',
        'http_service', 'open_port', 'discovered_url'
    )
);

-- =============================================================================
-- Step 2: Add sub_type column
-- =============================================================================

ALTER TABLE assets ADD COLUMN IF NOT EXISTS sub_type VARCHAR(50);

CREATE INDEX IF NOT EXISTS idx_assets_sub_type ON assets(tenant_id, sub_type) WHERE sub_type IS NOT NULL;

-- Backfill sub_type from current type for types being consolidated.
-- After backfill, type will be updated to the core type.
-- Order matters: backfill FIRST, then update type.

-- Step 1: Set sub_type = current type (preserves original identity)
UPDATE assets SET sub_type = 'firewall'        WHERE asset_type = 'firewall'        AND sub_type IS NULL;
UPDATE assets SET sub_type = 'load_balancer'   WHERE asset_type = 'load_balancer'   AND sub_type IS NULL;
UPDATE assets SET sub_type = 'vpc'             WHERE asset_type = 'vpc'             AND sub_type IS NULL;
UPDATE assets SET sub_type = 'subnet'          WHERE asset_type = 'subnet'          AND sub_type IS NULL;
UPDATE assets SET sub_type = 'compute'         WHERE asset_type = 'compute'         AND sub_type IS NULL;
UPDATE assets SET sub_type = 'serverless'      WHERE asset_type = 'serverless'      AND sub_type IS NULL;
UPDATE assets SET sub_type = 'website'         WHERE asset_type = 'website'         AND sub_type IS NULL;
UPDATE assets SET sub_type = 'web_application' WHERE asset_type = 'web_application' AND sub_type IS NULL;
UPDATE assets SET sub_type = 'api'             WHERE asset_type = 'api'             AND sub_type IS NULL;
UPDATE assets SET sub_type = 'mobile_app'      WHERE asset_type = 'mobile_app'      AND sub_type IS NULL;
UPDATE assets SET sub_type = 'iam_user'        WHERE asset_type = 'iam_user'        AND sub_type IS NULL;
UPDATE assets SET sub_type = 'iam_role'        WHERE asset_type = 'iam_role'        AND sub_type IS NULL;
UPDATE assets SET sub_type = 'service_account' WHERE asset_type = 'service_account' AND sub_type IS NULL;
UPDATE assets SET sub_type = 'data_store'      WHERE asset_type = 'data_store'      AND sub_type IS NULL;
UPDATE assets SET sub_type = 's3_bucket'       WHERE asset_type = 's3_bucket'       AND sub_type IS NULL;
UPDATE assets SET sub_type = 'container_registry' WHERE asset_type = 'container_registry' AND sub_type IS NULL;
UPDATE assets SET sub_type = 'kubernetes_cluster'  WHERE asset_type = 'kubernetes_cluster'  AND sub_type IS NULL;
UPDATE assets SET sub_type = 'kubernetes_namespace' WHERE asset_type = 'kubernetes_namespace' AND sub_type IS NULL;
UPDATE assets SET sub_type = 'http_service'    WHERE asset_type = 'http_service'    AND sub_type IS NULL;
UPDATE assets SET sub_type = 'open_port'       WHERE asset_type = 'open_port'       AND sub_type IS NULL;
UPDATE assets SET sub_type = 'discovered_url'  WHERE asset_type = 'discovered_url'  AND sub_type IS NULL;

-- Also set sub_type from device_role for hosts tagged as network-device
UPDATE assets SET sub_type = properties->>'device_role'
    WHERE asset_type = 'host'
    AND 'network-device' = ANY(tags)
    AND properties->>'device_role' IS NOT NULL
    AND sub_type IS NULL;

-- Step 2: Consolidate types (change asset_type to core type)
-- NOTE: This is the point of no return for type column.
-- The original type is preserved in sub_type.
UPDATE assets SET asset_type = 'network'       WHERE asset_type IN ('firewall', 'load_balancer', 'vpc', 'subnet');
UPDATE assets SET asset_type = 'host'          WHERE asset_type IN ('compute', 'serverless');
UPDATE assets SET asset_type = 'application'   WHERE asset_type IN ('website', 'web_application', 'api', 'mobile_app');
UPDATE assets SET asset_type = 'identity'      WHERE asset_type IN ('iam_user', 'iam_role', 'service_account');
UPDATE assets SET asset_type = 'database'      WHERE asset_type = 'data_store';
UPDATE assets SET asset_type = 'storage'       WHERE asset_type IN ('s3_bucket', 'container_registry');
UPDATE assets SET asset_type = 'kubernetes'    WHERE asset_type IN ('kubernetes_cluster', 'kubernetes_namespace');
UPDATE assets SET asset_type = 'service'       WHERE asset_type IN ('http_service', 'open_port', 'discovered_url');

-- Hosts tagged as network-device become type=network
UPDATE assets SET asset_type = 'network', sub_type = COALESCE(sub_type, 'unknown')
    WHERE asset_type = 'host'
    AND 'network-device' = ANY(tags)
    AND sub_type IS NOT NULL;
