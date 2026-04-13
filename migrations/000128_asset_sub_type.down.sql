-- Rollback: restore original types from sub_type, then drop column.
-- This reverses the type consolidation.

-- Restore original type from sub_type where sub_type matches old enum
UPDATE assets SET asset_type = sub_type
    WHERE sub_type IS NOT NULL
    AND sub_type IN (
        'firewall', 'load_balancer', 'vpc', 'subnet',
        'compute', 'serverless',
        'website', 'web_application', 'api', 'mobile_app',
        'iam_user', 'iam_role', 'service_account',
        'data_store', 's3_bucket', 'container_registry',
        'kubernetes_cluster', 'kubernetes_namespace',
        'http_service', 'open_port', 'discovered_url'
    );

-- Restore network-device hosts
UPDATE assets SET asset_type = 'host'
    WHERE asset_type = 'network'
    AND sub_type IN ('core_switch', 'access_switch', 'router', 'wireless_ap', 'ids_ips');

-- Restore application → original types
UPDATE assets SET asset_type = sub_type
    WHERE asset_type = 'application'
    AND sub_type IN ('website', 'web_application', 'api', 'mobile_app');

-- Restore kubernetes → original types
UPDATE assets SET asset_type = sub_type
    WHERE asset_type = 'kubernetes'
    AND sub_type IN ('kubernetes_cluster', 'kubernetes_namespace');

-- Restore identity → original types
UPDATE assets SET asset_type = sub_type
    WHERE asset_type = 'identity'
    AND sub_type IN ('iam_user', 'iam_role', 'service_account');

-- Drop column
DROP INDEX IF EXISTS idx_assets_sub_type;
ALTER TABLE assets DROP COLUMN IF EXISTS sub_type;
