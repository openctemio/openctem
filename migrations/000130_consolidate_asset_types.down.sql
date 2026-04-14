-- Restore original types from sub_type
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
    AND sub_type IN ('core_switch', 'access_switch', 'router', 'wireless_ap', 'ids_ips', 'unknown');
