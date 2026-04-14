-- =============================================================================
-- Migration 000130: Phase 3 — Consolidate asset_type values
-- =============================================================================
-- Prerequisites: 000128 (sub_type column + backfill), 000129 (legacy DB types)
-- Rollback: down.sql restores from sub_type
-- =============================================================================

-- Step 1: Ensure new consolidated types exist in asset_types master table (FK)
INSERT INTO asset_types (code, name, description, category_id, display_order, is_scannable, is_discoverable, is_active)
VALUES
    ('application', 'Application', 'Web apps, APIs, mobile apps',
     (SELECT id FROM asset_type_categories WHERE code = 'application'), 20, TRUE, TRUE, TRUE),
    ('identity', 'Identity', 'Users, roles, service accounts',
     (SELECT id FROM asset_type_categories WHERE code = 'identity'), 60, FALSE, TRUE, TRUE),
    ('kubernetes', 'Kubernetes', 'Clusters, namespaces, workloads',
     (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 45, TRUE, TRUE, TRUE)
ON CONFLICT (code) DO NOTHING;

-- Step 2: Consolidate types (sub_type already set by 000128)
UPDATE assets SET asset_type = 'network'     WHERE asset_type IN ('firewall', 'load_balancer', 'vpc', 'subnet');
UPDATE assets SET asset_type = 'host'        WHERE asset_type IN ('compute', 'serverless');
UPDATE assets SET asset_type = 'application' WHERE asset_type IN ('website', 'web_application', 'api', 'mobile_app');
UPDATE assets SET asset_type = 'identity'    WHERE asset_type IN ('iam_user', 'iam_role', 'service_account');
UPDATE assets SET asset_type = 'database'    WHERE asset_type = 'data_store';
UPDATE assets SET asset_type = 'storage'     WHERE asset_type IN ('s3_bucket', 'container_registry');
UPDATE assets SET asset_type = 'kubernetes'  WHERE asset_type IN ('kubernetes_cluster', 'kubernetes_namespace');
UPDATE assets SET asset_type = 'service'     WHERE asset_type IN ('http_service', 'open_port', 'discovered_url');

-- Step 3: Hosts tagged as network-device → type=network
UPDATE assets SET asset_type = 'network'
    WHERE asset_type = 'host'
    AND 'network-device' = ANY(tags)
    AND sub_type IS NOT NULL
    AND sub_type != '';
