-- =============================================================================
-- Migration 000491: one web sub-type (RFC-042 §6.3.8 O3)
-- =============================================================================
-- docs/rfcs/RFC-042-asset-inventory-v2.md, PR T4a. Owner decision O3: a web
-- application is stored as (application, website) and labelled "Web
-- application". `web_application` stays an accepted input, as a type name
-- (type_inputs) and as a sub-type of application (sub_type_inputs), and is no
-- longer a stored sub-type.
--
-- 1. The registry block below drops web_application from application's
--    closed sub-types and maps both inputs to (application, website).
-- 2. Every asset stored as (application, web_application) moves to
--    (application, website) through asset_type_normalise_batch (000490): the
--    move is ledgered (asset_type_reclassifications, migration 491), recorded
--    as a `reclassified` history entry, and nothing the asset has is
--    overwritten. Names do not change, so ids and every reference stay.
-- 3. Threat-model applicability rows keyed by (application, web_application)
--    move to (application, website); when that key already exists the
--    existing row wins. Each move is recorded in
--    technique_applicability_subtype_moves for the down migration.
--
-- Only type names and counts are logged.
-- expand-contract-ok: no column is dropped or renamed and no constraint is added. An old pod may still store (application, web_application) until it is replaced; nothing refuses it, the readers treat both sub-types alike, and every later T4a migration re-runs asset_type_normalise_batch, which moves such rows.
-- =============================================================================

-- BEGIN asset-type-registry (registry version 4449e500ad1d69fe)
-- Generated from api/configs/asset-types.yaml by `make asset-types-sql`.
-- Do not edit: `go run ./cmd/gen-asset-types -check` compares this block
-- with the YAML.
ALTER TABLE asset_types DROP CONSTRAINT IF EXISTS chk_asset_types_class;
ALTER TABLE asset_types ADD CONSTRAINT chk_asset_types_class CHECK (class IN ('domain', 'ip_address', 'certificate', 'service', 'web_endpoint', 'application', 'host', 'function', 'cloud_account', 'container', 'cluster', 'artifact_registry', 'code_repo', 'identity', 'data_store', 'network', 'other'));
ALTER TABLE asset_types DROP CONSTRAINT IF EXISTS chk_asset_types_lens;
ALTER TABLE asset_types ADD CONSTRAINT chk_asset_types_lens CHECK (lens IS NULL OR lens IN ('external_surface', 'applications', 'cloud_infra', 'containers_k8s', 'code', 'identities', 'data', 'network'));

INSERT INTO asset_types (code, name, class, lens, alias_of, alias_sub_type, sub_types, is_storable) VALUES
    ('domain', 'Domain', 'domain', 'external_surface', NULL, NULL, '{}', true),
    ('subdomain', 'Subdomain', 'domain', 'external_surface', NULL, NULL, '{}', true),
    ('ip_address', 'IP Address', 'ip_address', 'external_surface', NULL, NULL, '{}', true),
    ('certificate', 'Certificate', 'certificate', 'external_surface', NULL, NULL, '{}', true),
    ('service', 'Service', 'service', 'external_surface', NULL, NULL, ARRAY['http', 'open_port', 'discovered_url']::text[], true),
    ('http_service', 'HTTP Service', 'service', 'external_surface', 'service', 'http', '{}', false),
    ('open_port', 'Open Port', 'service', 'external_surface', 'service', 'open_port', '{}', false),
    ('discovered_url', 'Discovered URL', 'web_endpoint', 'external_surface', 'service', 'discovered_url', '{}', false),
    ('application', 'Application', 'application', 'applications', NULL, NULL, ARRAY['website', 'api', 'mobile_app']::text[], true),
    ('website', 'Web Application', 'application', 'applications', 'application', 'website', '{}', false),
    ('api', 'API', 'application', 'applications', 'application', 'api', '{}', false),
    ('mobile_app', 'Mobile App', 'application', 'applications', 'application', 'mobile_app', '{}', false),
    ('host', 'Host', 'host', 'cloud_infra', NULL, NULL, ARRAY['compute', 'serverless']::text[], true),
    ('compute', 'Compute Instance', 'host', 'cloud_infra', 'host', 'compute', '{}', false),
    ('endpoint', 'Endpoint', 'host', 'cloud_infra', NULL, NULL, '{}', true),
    ('serverless', 'Serverless Function', 'function', 'cloud_infra', 'host', 'serverless', '{}', false),
    ('cloud_account', 'Cloud Account', 'cloud_account', 'cloud_infra', NULL, NULL, ARRAY['account', 'project', 'subscription', 'organization']::text[], true),
    ('container', 'Container', 'container', 'containers_k8s', NULL, NULL, ARRAY['image']::text[], true),
    ('kubernetes', 'Kubernetes', 'cluster', 'containers_k8s', NULL, NULL, ARRAY['cluster', 'namespace', 'workload']::text[], true),
    ('kubernetes_cluster', 'Kubernetes Cluster', 'cluster', 'containers_k8s', 'kubernetes', 'cluster', '{}', false),
    ('kubernetes_namespace', 'Kubernetes Namespace', 'cluster', 'containers_k8s', 'kubernetes', 'namespace', '{}', false),
    ('container_registry', 'Container Registry', 'artifact_registry', 'containers_k8s', 'storage', 'container_registry', '{}', false),
    ('repository', 'Repository', 'code_repo', 'code', NULL, NULL, '{}', true),
    ('identity', 'Identity', 'identity', 'identities', NULL, NULL, ARRAY['iam_user', 'iam_role', 'service_account', 'identity_provider']::text[], true),
    ('iam_user', 'IAM User', 'identity', 'identities', 'identity', 'iam_user', '{}', false),
    ('iam_role', 'IAM Role', 'identity', 'identities', 'identity', 'iam_role', '{}', false),
    ('service_account', 'Service Account', 'identity', 'identities', 'identity', 'service_account', '{}', false),
    ('database', 'Database', 'data_store', 'data', NULL, NULL, ARRAY['relational', 'document', 'key_value', 'graph', 'warehouse', 'vector']::text[], true),
    ('data_store', 'Data Store', 'data_store', 'data', 'database', NULL, '{}', false),
    ('storage', 'Storage', 'data_store', 'data', NULL, NULL, ARRAY['bucket', 'file_share', 'disk', 'container_registry']::text[], true),
    ('s3_bucket', 'S3 Bucket', 'data_store', 'data', 'storage', 'bucket', '{}', false),
    ('network', 'Network', 'network', 'network', NULL, NULL, ARRAY['vpc', 'subnet', 'ip_block', 'vlan', 'security_group', 'firewall', 'router', 'switch', 'load_balancer', 'vpn_gateway', 'wireless_controller', 'access_point', 'ids_ips']::text[], true),
    ('vpc', 'VPC', 'network', 'network', 'network', 'vpc', '{}', false),
    ('subnet', 'Subnet', 'network', 'network', 'network', 'subnet', '{}', false),
    ('firewall', 'Firewall', 'network', 'network', 'network', 'firewall', '{}', false),
    ('load_balancer', 'Load Balancer', 'network', 'network', 'network', 'load_balancer', '{}', false),
    ('unclassified', 'Unclassified', 'other', NULL, NULL, NULL, '{}', true)
ON CONFLICT (code) DO UPDATE SET
    class = EXCLUDED.class,
    lens = EXCLUDED.lens,
    alias_of = EXCLUDED.alias_of,
    alias_sub_type = EXCLUDED.alias_sub_type,
    sub_types = EXCLUDED.sub_types,
    is_storable = EXCLUDED.is_storable;

-- Codes that are not registry types (legacy rows kept for the assets FK).
UPDATE asset_types SET class = 'other', lens = NULL, alias_of = NULL, alias_sub_type = NULL,
    sub_types = '{}', is_storable = false
WHERE code NOT IN ('domain', 'subdomain', 'ip_address', 'certificate', 'service', 'http_service', 'open_port', 'discovered_url', 'application', 'website', 'api', 'mobile_app', 'host', 'compute', 'endpoint', 'serverless', 'cloud_account', 'container', 'kubernetes', 'kubernetes_cluster', 'kubernetes_namespace', 'container_registry', 'repository', 'identity', 'iam_user', 'iam_role', 'service_account', 'database', 'data_store', 'storage', 's3_bucket', 'network', 'vpc', 'subnet', 'firewall', 'load_balancer', 'unclassified');

-- Accepted inputs that are not stored as such: aliases (from_sub_type '')
-- and legacy sub-types, with what they are stored as.
DELETE FROM asset_type_input_map;
INSERT INTO asset_type_input_map (from_type, from_sub_type, to_type, to_sub_type, provider, attributes) VALUES
    ('ip_address', 'ip', 'ip_address', NULL, NULL, '{}'),
    ('certificate', 'ssl', 'certificate', NULL, NULL, '{}'),
    ('certificate', 'tls', 'certificate', NULL, NULL, '{}'),
    ('service', 'port', 'service', 'open_port', NULL, '{}'),
    ('http_service', '', 'service', 'http', NULL, '{}'),
    ('open_port', '', 'service', 'open_port', NULL, '{}'),
    ('discovered_url', '', 'service', 'discovered_url', NULL, '{}'),
    ('application', 'web_application', 'application', 'website', NULL, '{}'),
    ('website', '', 'application', 'website', NULL, '{}'),
    ('api', '', 'application', 'api', NULL, '{}'),
    ('mobile_app', '', 'application', 'mobile_app', NULL, '{}'),
    ('host', 'bsd', 'host', NULL, NULL, '{"os_family":"bsd"}'),
    ('host', 'kubernetes_cluster', 'kubernetes', 'cluster', NULL, '{}'),
    ('host', 'linux', 'host', NULL, NULL, '{"os_family":"linux"}'),
    ('host', 'macos', 'host', NULL, NULL, '{"os_family":"macos"}'),
    ('host', 'server', 'host', NULL, NULL, '{}'),
    ('host', 'windows', 'host', NULL, NULL, '{"os_family":"windows"}'),
    ('compute', '', 'host', 'compute', NULL, '{}'),
    ('serverless', '', 'host', 'serverless', NULL, '{}'),
    ('cloud_account', 'aws', 'cloud_account', NULL, 'aws', '{"provider":"aws"}'),
    ('cloud_account', 'azure', 'cloud_account', NULL, 'azure', '{"provider":"azure"}'),
    ('cloud_account', 'digitalocean', 'cloud_account', NULL, NULL, '{"provider":"digitalocean"}'),
    ('cloud_account', 'gcp', 'cloud_account', NULL, 'gcp', '{"provider":"gcp"}'),
    ('container', 'cronjob', 'kubernetes', 'workload', NULL, '{"workload_kind":"cronjob"}'),
    ('container', 'daemonset', 'kubernetes', 'workload', NULL, '{"workload_kind":"daemonset"}'),
    ('container', 'deployment', 'kubernetes', 'workload', NULL, '{"workload_kind":"deployment"}'),
    ('container', 'job', 'kubernetes', 'workload', NULL, '{"workload_kind":"job"}'),
    ('container', 'pod', 'kubernetes', 'workload', NULL, '{"workload_kind":"pod"}'),
    ('container', 'replicaset', 'kubernetes', 'workload', NULL, '{"workload_kind":"replicaset"}'),
    ('container', 'statefulset', 'kubernetes', 'workload', NULL, '{"workload_kind":"statefulset"}'),
    ('kubernetes_cluster', '', 'kubernetes', 'cluster', NULL, '{}'),
    ('kubernetes_namespace', '', 'kubernetes', 'namespace', NULL, '{}'),
    ('container_registry', '', 'storage', 'container_registry', NULL, '{}'),
    ('repository', 'azure_devops', 'repository', NULL, 'azure_devops', '{"provider":"azure_devops"}'),
    ('repository', 'bitbucket', 'repository', NULL, 'bitbucket', '{"provider":"bitbucket"}'),
    ('repository', 'github', 'repository', NULL, 'github', '{"provider":"github"}'),
    ('repository', 'gitlab', 'repository', NULL, 'gitlab', '{"provider":"gitlab"}'),
    ('iam_user', '', 'identity', 'iam_user', NULL, '{}'),
    ('iam_role', '', 'identity', 'iam_role', NULL, '{}'),
    ('service_account', '', 'identity', 'service_account', NULL, '{}'),
    ('database', 'bigquery', 'database', 'warehouse', NULL, '{"engine":"bigquery"}'),
    ('database', 'cassandra', 'database', 'key_value', NULL, '{"engine":"cassandra"}'),
    ('database', 'couchdb', 'database', 'document', NULL, '{"engine":"couchdb"}'),
    ('database', 'data_store', 'database', NULL, NULL, '{}'),
    ('database', 'dynamodb', 'database', 'key_value', NULL, '{"engine":"dynamodb"}'),
    ('database', 'elasticsearch', 'database', 'document', NULL, '{"engine":"elasticsearch"}'),
    ('database', 'mariadb', 'database', 'relational', NULL, '{"engine":"mariadb"}'),
    ('database', 'memcached', 'database', 'key_value', NULL, '{"engine":"memcached"}'),
    ('database', 'mongodb', 'database', 'document', NULL, '{"engine":"mongodb"}'),
    ('database', 'mssql', 'database', 'relational', NULL, '{"engine":"mssql"}'),
    ('database', 'mysql', 'database', 'relational', NULL, '{"engine":"mysql"}'),
    ('database', 'neo4j', 'database', 'graph', NULL, '{"engine":"neo4j"}'),
    ('database', 'opensearch', 'database', 'document', NULL, '{"engine":"opensearch"}'),
    ('database', 'oracle', 'database', 'relational', NULL, '{"engine":"oracle"}'),
    ('database', 'postgres', 'database', 'relational', NULL, '{"engine":"postgresql"}'),
    ('database', 'postgresql', 'database', 'relational', NULL, '{"engine":"postgresql"}'),
    ('database', 'redis', 'database', 'key_value', NULL, '{"engine":"redis"}'),
    ('database', 'redshift', 'database', 'warehouse', NULL, '{"engine":"redshift"}'),
    ('database', 'snowflake', 'database', 'warehouse', NULL, '{"engine":"snowflake"}'),
    ('database', 'sqlite', 'database', 'relational', NULL, '{"engine":"sqlite"}'),
    ('database', 'sqlserver', 'database', 'relational', NULL, '{"engine":"mssql"}'),
    ('data_store', '', 'database', NULL, NULL, '{}'),
    ('storage', 's3', 'storage', 'bucket', 'aws', '{"provider":"aws"}'),
    ('storage', 's3_bucket', 'storage', 'bucket', 'aws', '{"provider":"aws"}'),
    ('s3_bucket', '', 'storage', 'bucket', 'aws', '{"provider":"aws"}'),
    ('network', 'access_switch', 'network', 'switch', NULL, '{}'),
    ('network', 'core_switch', 'network', 'switch', NULL, '{}'),
    ('network', 'ids', 'network', 'ids_ips', NULL, '{}'),
    ('network', 'ips', 'network', 'ids_ips', NULL, '{}'),
    ('network', 'wireless_ap', 'network', 'access_point', NULL, '{}'),
    ('vpc', '', 'network', 'vpc', NULL, '{}'),
    ('subnet', '', 'network', 'subnet', NULL, '{}'),
    ('firewall', '', 'network', 'firewall', NULL, '{}'),
    ('load_balancer', '', 'network', 'load_balancer', NULL, '{}'),
    ('web_application', '', 'application', 'website', NULL, '{}');

-- Re-derive assets.asset_class / asset_lens in batches, without touching
-- updated_at.
ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
DO $$
DECLARE
    cursor_id uuid := NULL;
BEGIN
    LOOP
        SELECT b.last_id INTO cursor_id FROM asset_registry_backfill(cursor_id, 5000) b;
        EXIT WHEN cursor_id IS NULL;
    END LOOP;
END $$;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;

-- Only core types are stored (RFC-042 §6.3.8). VALIDATE takes a SHARE
-- UPDATE EXCLUSIVE lock: writers keep running.
ALTER TABLE assets DROP CONSTRAINT IF EXISTS chk_assets_core_type;
ALTER TABLE assets ADD CONSTRAINT chk_assets_core_type CHECK (asset_type IN ('domain', 'subdomain', 'ip_address', 'certificate', 'service', 'application', 'host', 'endpoint', 'cloud_account', 'container', 'kubernetes', 'repository', 'identity', 'database', 'storage', 'network', 'unclassified')) NOT VALID;
ALTER TABLE assets VALIDATE CONSTRAINT chk_assets_core_type;
-- END asset-type-registry

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
DO $$
DECLARE
    cursor_id uuid := NULL;
    total     int := 0;
    b         record;
BEGIN
    LOOP
        SELECT * INTO b FROM asset_type_normalise_batch(cursor_id, 5000, 491);
        EXIT WHEN b.last_id IS NULL;
        total := total + b.moved;
        cursor_id := b.last_id;
    END LOOP;
    RAISE NOTICE '000491: % asset row(s) moved to application/website', total;
END $$;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;

CREATE TABLE IF NOT EXISTS technique_applicability_subtype_moves (
    migration            INT NOT NULL,
    technique_id         VARCHAR(20) NOT NULL,
    asset_type           VARCHAR(50) NOT NULL,
    old_sub_type         VARCHAR(50) NOT NULL,
    new_sub_type         VARCHAR(50) NOT NULL,
    dataset_version      VARCHAR(20) NOT NULL,
    edge_type            VARCHAR(40),
    min_network          VARCHAR(20),
    min_credential       VARCHAR(20),
    requires_persistence BOOLEAN,
    inserted             BOOLEAN NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (migration, technique_id, asset_type, old_sub_type, dataset_version)
);

COMMENT ON TABLE technique_applicability_subtype_moves IS 'RFC-042 §6.3.8: technique_applicability rows moved to another sub-type by a T4a migration; read by its down migration';

WITH moved AS (
    DELETE FROM technique_applicability t
    WHERE t.asset_type = 'application' AND t.sub_type = 'web_application'
    RETURNING t.technique_id, t.asset_type, t.sub_type AS old_sub_type, t.dataset_version,
              t.edge_type, t.min_network, t.min_credential, t.requires_persistence
), ins AS (
    INSERT INTO technique_applicability
        (technique_id, asset_type, sub_type, edge_type, min_network, min_credential,
         requires_persistence, dataset_version)
    SELECT technique_id, asset_type, 'website', edge_type, min_network, min_credential,
           requires_persistence, dataset_version
    FROM moved
    ON CONFLICT (technique_id, asset_type, sub_type, dataset_version) DO NOTHING
    RETURNING technique_id, dataset_version
)
INSERT INTO technique_applicability_subtype_moves
    (migration, technique_id, asset_type, old_sub_type, new_sub_type, dataset_version,
     edge_type, min_network, min_credential, requires_persistence, inserted)
SELECT 491, mv.technique_id, mv.asset_type, mv.old_sub_type, 'website', mv.dataset_version,
       mv.edge_type, mv.min_network, mv.min_credential, mv.requires_persistence,
       (i.technique_id IS NOT NULL)
FROM moved mv
LEFT JOIN ins i ON i.technique_id = mv.technique_id AND i.dataset_version = mv.dataset_version;
