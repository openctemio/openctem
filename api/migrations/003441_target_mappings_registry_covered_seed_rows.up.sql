-- The asset type registry (configs/asset-types.yaml, scannable_by) decides which
-- asset types a tool target type can scan; target_asset_type_mappings only adds
-- pairs on top of it. These seeded rows say what the registry already says, so
-- they are removed and the table keeps administrators' additions (and any seed
-- row that goes beyond the registry). Rows an administrator created have a
-- created_by and are never touched.

DELETE FROM target_asset_type_mappings
WHERE created_by IS NULL
  AND (target_type, asset_type) IN (
    ('url', 'website'),
    ('url', 'api'),
    ('url', 'http_service'),
    ('url', 'discovered_url'),
    ('domain', 'domain'),
    ('domain', 'subdomain'),
    ('host', 'compute'),
    ('repository', 'repository'),
    ('file', 'repository'),
    ('container', 'container'),
    ('container', 'container_registry'),
    ('kubernetes', 'kubernetes_cluster'),
    ('kubernetes', 'kubernetes_namespace'),
    ('network', 'network'),
    ('network', 'subnet'),
    ('network', 'vpc'),
    ('network', 'firewall'),
    ('network', 'load_balancer'),
    ('service', 'open_port'),
    ('service', 'http_service'),
    ('port', 'open_port'),
    ('database', 'database'),
    ('database', 'data_store'),
    ('mobile', 'mobile_app'),
    ('api', 'api'),
    ('certificate', 'certificate'),
    ('cloud_account', 'cloud_account'),
    ('compute', 'compute'),
    ('storage', 's3_bucket'),
    ('ip', 'ip_address'),
    ('host', 'ip_address'),
    ('serverless', 'serverless')
  );
