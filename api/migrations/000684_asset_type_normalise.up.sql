-- =============================================================================
-- Migration 000684: normalise stored asset types to the registry
-- =============================================================================
-- RFC-042 §6.3.8.1 (docs/rfcs/RFC-042-asset-inventory-v2.md), PR T3. Only
-- core types are stored: every writer resolves its input since 000400, but
-- rows written before still hold alias names (website, s3_bucket ...),
-- vendor or engine sub-types (cloud_account/aws, database/postgresql),
-- undeclared sub-types and 14 legacy codes that are not registry types.
--
-- Every stored (asset_type, sub_type) pair that is not a core type with a
-- declared sub-type is moved, in batches of 5,000 by id:
--
--   input       an accepted input (alias or legacy sub-type) is stored as
--               asset_type_input_map says (000400, generated from the YAML),
--               with its provider and attributes;
--   alias       an alias name with another sub-type is stored as the alias;
--               the other sub-type is kept, or recorded as an attribute;
--   legacy_code one of the 14 legacy codes is stored as
--               asset_type_legacy_codes says, and the code is kept in
--               properties.x_native_type;
--   undeclared  a core type with an undeclared sub-type keeps its type; the
--               sub-type moves to properties.x_native_sub_type.
--
-- Nothing is dropped: a value that does not fit is kept as an x_native_*
-- property, an existing property, provider or sub-type is never overwritten,
-- and every move is written to asset_type_reclassifications in the same
-- transaction, which the down migration replays. Names do not change, so
-- the (tenant_id, name) key cannot collide and every asset keeps its id
-- (findings, identifiers, relationships, groups, owners, history).
--
-- Each moved asset gets one `reclassified` state-history row. Applications
-- that now share a host within a tenant are queued for the RFC-043 dedup
-- review (reason type_consolidation); nothing is merged automatically.
-- Legacy asset_types rows no asset uses any more are removed (kept in
-- asset_types_legacy_removed for the down migration); the FK is ON DELETE
-- RESTRICT, so a stray reference fails loudly. Last, the registry block adds
-- chk_assets_core_type (NOT VALID, then VALIDATE).
--
-- Only type names and counts are logged; no tenant or asset name.
-- expand-contract-ok: no column is dropped or renamed. The deleted asset_types rows are legacy codes no asset holds after the moves above, which no code path reads (the registry is the source of truth since 000310), and old pods write only core types since 000400 (T1), so the new CHECK does not refuse their writes.
-- =============================================================================

-- What each legacy code is stored as. A legacy code is not a registry type,
-- so it is mapped here, once; the code itself is kept in x_native_type.
CREATE TABLE IF NOT EXISTS asset_type_legacy_codes (
    code        VARCHAR(50) PRIMARY KEY,
    to_type     VARCHAR(50) NOT NULL,
    to_sub_type VARCHAR(50)
);

COMMENT ON TABLE asset_type_legacy_codes IS 'RFC-042 §6.3.8: what each legacy asset_types code was normalised to by 000684';

INSERT INTO asset_type_legacy_codes (code, to_type, to_sub_type) VALUES
    ('ip',                  'ip_address',   NULL),
    ('ip_range',            'network',      'ip_block'),
    ('server',              'host',         NULL),
    ('hardware',            'host',         NULL),
    ('iot_device',          'host',         NULL),
    ('ssl_certificate',     'certificate',  NULL),
    ('port',                'service',      'open_port'),
    ('serverless_function', 'host',         'serverless'),
    ('container_image',     'container',    'image'),
    ('user_account',        'identity',     NULL),
    ('code_artifact',       'unclassified', NULL),
    ('cloud_resource',      'unclassified', NULL),
    ('credential',          'unclassified', NULL),
    ('other',               'unclassified', NULL)
ON CONFLICT (code) DO NOTHING;

CREATE TABLE IF NOT EXISTS asset_type_reclassifications (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    migration     INT NOT NULL,
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id      UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    rule          VARCHAR(20) NOT NULL,
    old_type      VARCHAR(50) NOT NULL,
    old_sub_type  VARCHAR(50),
    old_provider  VARCHAR(50),
    new_type      VARCHAR(50) NOT NULL,
    new_sub_type  VARCHAR(50),
    new_provider  VARCHAR(50),
    added         JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asset_type_reclassifications_migration
    ON asset_type_reclassifications (migration, asset_id);

COMMENT ON TABLE asset_type_reclassifications IS 'RFC-042 §6.3.8: ledger of the asset type normalisation (000684); added = the properties it set, which the down migration removes when unchanged';

CREATE TABLE IF NOT EXISTS asset_types_legacy_removed (
    code       VARCHAR(50) PRIMARY KEY,
    row_data   JSONB NOT NULL,
    removed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE asset_types_legacy_removed IS 'RFC-042 §6.3.8: legacy asset_types rows removed by 000684, restored by its down migration';

-- p_migration names the migration that runs it: the boundary fixes of
-- RFC-042 §6.3.8 (T4a) reuse this function, each with its own ledger rows.
CREATE OR REPLACE FUNCTION asset_type_normalise_batch(p_after UUID, p_batch INT, p_migration INT,
                                                      OUT last_id UUID, OUT moved INT)
LANGUAGE plpgsql AS $$
DECLARE
    r            record;
    m            record;
    new_type     text;
    new_sub      text;
    new_provider text;
    attrs        jsonb;
    rule         text;
    left_sub     text;
    added        jsonb;
    label_old    text;
    label_new    text;
BEGIN
    moved := 0;
    SELECT page.id INTO last_id FROM (
        SELECT id FROM assets
        WHERE p_after IS NULL OR id > p_after
        ORDER BY id
        LIMIT p_batch
    ) page
    ORDER BY page.id DESC
    LIMIT 1;
    IF last_id IS NULL THEN
        RETURN;
    END IF;

    FOR r IN
        SELECT a.id, a.tenant_id, a.asset_type, NULLIF(a.sub_type, '') AS sub_type,
               a.provider, a.properties
        FROM assets a
        LEFT JOIN asset_types t ON t.code = a.asset_type
        WHERE (p_after IS NULL OR a.id > p_after) AND a.id <= last_id
          AND NOT (COALESCE(t.is_storable, false)
                   AND (NULLIF(a.sub_type, '') IS NULL OR a.sub_type = ANY (t.sub_types)))
        ORDER BY a.id
    LOOP
        new_provider := NULL;
        attrs := '{}'::jsonb;
        left_sub := r.sub_type;

        SELECT * INTO m FROM asset_type_input_map
        WHERE from_type = r.asset_type AND from_sub_type = COALESCE(r.sub_type, '');
        IF FOUND THEN
            rule := 'input';
            new_type := m.to_type;
            new_sub := m.to_sub_type;
            new_provider := m.provider;
            attrs := m.attributes;
            left_sub := NULL; -- the sub-type was the input itself
        ELSE
            SELECT * INTO m FROM asset_type_input_map
            WHERE from_type = r.asset_type AND from_sub_type = '';
            IF FOUND THEN
                rule := 'alias';
                new_type := m.to_type;
                new_sub := m.to_sub_type;
                new_provider := m.provider;
                attrs := m.attributes;
            ELSE
                SELECT * INTO m FROM asset_type_legacy_codes WHERE code = r.asset_type;
                IF FOUND THEN
                    rule := 'legacy_code';
                    new_type := m.to_type;
                    new_sub := m.to_sub_type;
                    attrs := jsonb_build_object('x_native_type', r.asset_type);
                ELSIF EXISTS (SELECT 1 FROM asset_types WHERE code = r.asset_type AND is_storable) THEN
                    rule := 'undeclared';
                    new_type := r.asset_type;
                    new_sub := NULL;
                ELSE
                    -- Not a registry type and not a known legacy code: kept
                    -- as an unclassified asset that remembers its type.
                    rule := 'legacy_code';
                    new_type := 'unclassified';
                    new_sub := NULL;
                    attrs := jsonb_build_object('x_native_type', r.asset_type);
                END IF;
            END IF;
        END IF;

        -- A sub-type the input did not account for is kept when it is a
        -- declared kind of the new type, else recorded as an attribute.
        IF left_sub IS NOT NULL AND left_sub IS DISTINCT FROM new_sub THEN
            IF new_sub IS NULL AND EXISTS (
                SELECT 1 FROM asset_types WHERE code = new_type AND left_sub = ANY (sub_types)
            ) THEN
                new_sub := left_sub;
            ELSE
                attrs := attrs || jsonb_build_object('x_native_sub_type', left_sub);
            END IF;
        END IF;

        -- A provider the asset already names wins over the one the input
        -- implied (cloud_account/aws on a gcp account); the input's value is
        -- then kept as the native sub-type instead of a contradicting
        -- properties.provider.
        IF COALESCE(NULLIF(r.provider, ''), 'other') <> 'other'
           AND attrs ? 'provider' AND attrs->>'provider' <> r.provider THEN
            attrs := (attrs - 'provider') || jsonb_build_object('x_native_sub_type', COALESCE(r.sub_type, r.asset_type));
        END IF;

        -- Never overwrite: only the properties the asset does not have.
        SELECT COALESCE(jsonb_object_agg(e.key, e.value), '{}'::jsonb) INTO added
        FROM jsonb_each(attrs) e
        WHERE NOT (r.properties ? e.key);

        IF new_provider IS NULL OR COALESCE(NULLIF(r.provider, ''), 'other') <> 'other' THEN
            new_provider := r.provider;
        END IF;

        UPDATE assets
           SET asset_type = new_type,
               sub_type = new_sub,
               provider = new_provider,
               properties = properties || added
         WHERE id = r.id;

        INSERT INTO asset_type_reclassifications
            (migration, tenant_id, asset_id, rule, old_type, old_sub_type, old_provider,
             new_type, new_sub_type, new_provider, added)
        VALUES (p_migration, r.tenant_id, r.id, rule, r.asset_type, r.sub_type, r.provider,
                new_type, new_sub, new_provider, added);

        label_old := r.asset_type || COALESCE('/' || r.sub_type, '');
        label_new := new_type || COALESCE('/' || new_sub, '');
        INSERT INTO asset_state_history
            (tenant_id, asset_id, change_type, field, old_value, new_value, reason, source, metadata)
        VALUES (r.tenant_id, r.id, 'reclassified', 'asset_type', label_old, label_new,
                'Asset type normalised to the asset type registry (RFC-042 §6.3.8)', 'system',
                jsonb_build_object('migration', p_migration, 'rule', rule));

        moved := moved + 1;
    END LOOP;
END $$;

-- Pre-flight report, then the moves.
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT a.asset_type, COALESCE(a.sub_type, '') AS sub_type, count(*) AS n
        FROM assets a
        LEFT JOIN asset_types t ON t.code = a.asset_type
        WHERE NOT (COALESCE(t.is_storable, false)
                   AND (NULLIF(a.sub_type, '') IS NULL OR a.sub_type = ANY (t.sub_types)))
        GROUP BY 1, 2
        ORDER BY 1, 2
    LOOP
        RAISE NOTICE '000684: moving % asset row(s) stored as % / %', r.n, quote_literal(r.asset_type), quote_literal(r.sub_type);
    END LOOP;
END $$;

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
DO $$
DECLARE
    cursor_id uuid := NULL;
    total     int := 0;
    b         record;
BEGIN
    LOOP
        SELECT * INTO b FROM asset_type_normalise_batch(cursor_id, 5000, 684);
        EXIT WHEN b.last_id IS NULL;
        total := total + b.moved;
        cursor_id := b.last_id;
    END LOOP;
    RAISE NOTICE '000684: % asset row(s) normalised', total;
END $$;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;

-- Applications that now share a host within a tenant: queued for review,
-- never merged here. Only groups that contain a moved asset.
WITH moved AS (
    SELECT DISTINCT tenant_id, asset_id FROM asset_type_reclassifications WHERE migration = 684
), cand AS (
    SELECT a.id, a.tenant_id, a.name, a.created_at, (m.asset_id IS NOT NULL) AS was_moved,
           lower(rtrim(split_part(split_part(split_part(
               regexp_replace(a.name, '^[A-Za-z][A-Za-z0-9+.-]*://', ''), '/', 1), '?', 1), ':', 1), '.')) AS host
    FROM assets a
    LEFT JOIN moved m ON m.asset_id = a.id
    WHERE a.asset_type = 'application'
      AND a.tenant_id IN (SELECT tenant_id FROM moved)
      AND a.deleted_at IS NULL
), groups AS (
    SELECT tenant_id, host,
           array_agg(id ORDER BY created_at, id) AS ids,
           array_agg(name::text ORDER BY created_at, id) AS names
    FROM cand
    WHERE host <> ''
    GROUP BY tenant_id, host
    HAVING count(*) > 1 AND bool_or(was_moved)
)
INSERT INTO asset_dedup_review
    (tenant_id, normalized_name, asset_type, keep_asset_id, keep_asset_name,
     merge_asset_ids, merge_asset_names, reason, evidence)
SELECT tenant_id, host, 'application', ids[1], names[1], ids[2:], names[2:],
       'type_consolidation', jsonb_build_object('migration', 684, 'rule', 'same host after type normalisation')
FROM groups
ON CONFLICT (tenant_id, keep_asset_id) WHERE status = 'pending' DO NOTHING;

-- Legacy codes no asset uses any more.
WITH gone AS (
    DELETE FROM asset_types t
    WHERE t.code IN (SELECT code FROM asset_type_legacy_codes)
      AND NOT EXISTS (SELECT 1 FROM assets a WHERE a.asset_type = t.code)
    RETURNING t.*
)
INSERT INTO asset_types_legacy_removed (code, row_data)
SELECT gone.code, to_jsonb(gone) FROM gone
ON CONFLICT (code) DO NOTHING;

-- BEGIN asset-type-registry (registry version 86e61f2533871e72)
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
    ('application', 'Application', 'application', 'applications', NULL, NULL, ARRAY['website', 'web_application', 'api', 'mobile_app']::text[], true),
    ('website', 'Website', 'application', 'applications', 'application', 'website', '{}', false),
    ('web_application', 'Web Application', 'application', 'applications', 'application', 'web_application', '{}', false),
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
WHERE code NOT IN ('domain', 'subdomain', 'ip_address', 'certificate', 'service', 'http_service', 'open_port', 'discovered_url', 'application', 'website', 'web_application', 'api', 'mobile_app', 'host', 'compute', 'endpoint', 'serverless', 'cloud_account', 'container', 'kubernetes', 'kubernetes_cluster', 'kubernetes_namespace', 'container_registry', 'repository', 'identity', 'iam_user', 'iam_role', 'service_account', 'database', 'data_store', 'storage', 's3_bucket', 'network', 'vpc', 'subnet', 'firewall', 'load_balancer', 'unclassified');

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
    ('website', '', 'application', 'website', NULL, '{}'),
    ('web_application', '', 'application', 'web_application', NULL, '{}'),
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
    ('load_balancer', '', 'network', 'load_balancer', NULL, '{}');

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
