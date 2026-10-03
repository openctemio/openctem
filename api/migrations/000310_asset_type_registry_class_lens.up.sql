-- =============================================================================
-- Migration 000310: asset class and lens from the type registry
-- =============================================================================
-- RFC-042 §6.3 and §9.1 slice 1 (docs/rfcs/RFC-042-asset-inventory-v2.md).
--
-- api/configs/asset-types.yaml declares, per asset type, a class (16 + other)
-- and the lens that class belongs to. This migration:
--
--   1. adds asset_types.class / lens / alias_of / alias_sub_type, seeded from
--      the YAML (the generated block at the end);
--   2. adds assets.asset_class / asset_lens, kept in step with asset_type and
--      sub_type by a trigger, and backfills them in batches.
--
-- An alias keeps its own class even though ingest stores it as
-- (core type, sub_type): a `host` row with sub_type `serverless` is class
-- `function`, a `storage` row with sub_type `container_registry` is
-- `artifact_registry`, a `service` row with sub_type `discovered_url` is
-- `web_endpoint`. pkg/domain/asset.ClassOf applies the same rule in Go.
--
-- It also seeds the `endpoint` type, which the Go code has had since #343
-- but asset_types never had, so creating an endpoint asset failed the
-- assets.asset_type FK.
--
-- The indexes on assets are created CONCURRENTLY by 000311 and 000312.
-- =============================================================================

ALTER TABLE asset_types
    ADD COLUMN IF NOT EXISTS class VARCHAR(32) NOT NULL DEFAULT 'other',
    ADD COLUMN IF NOT EXISTS lens VARCHAR(32),
    ADD COLUMN IF NOT EXISTS alias_of VARCHAR(50),
    ADD COLUMN IF NOT EXISTS alias_sub_type VARCHAR(50);

-- One alias per stored (core type, sub_type) pair.
CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_types_alias
    ON asset_types (alias_of, alias_sub_type)
    WHERE alias_of IS NOT NULL;

COMMENT ON COLUMN asset_types.class IS 'RFC-042 asset class, from api/configs/asset-types.yaml';
COMMENT ON COLUMN asset_types.lens IS 'RFC-042 lens of the class (NULL for class other)';
COMMENT ON COLUMN asset_types.alias_of IS 'Core type this legacy type is stored as (with alias_sub_type)';
COMMENT ON COLUMN asset_types.alias_sub_type IS 'sub_type this legacy type is stored with';

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS asset_class VARCHAR(32),
    ADD COLUMN IF NOT EXISTS asset_lens VARCHAR(32);

COMMENT ON COLUMN assets.asset_class IS 'RFC-042 class, derived from (asset_type, sub_type) by trg_assets_registry_class; never written by the app';
COMMENT ON COLUMN assets.asset_lens IS 'RFC-042 lens, derived with asset_class; NULL for class other';

-- The class and lens of a stored (asset_type, sub_type) pair.
CREATE OR REPLACE FUNCTION asset_type_classification(p_type TEXT, p_sub_type TEXT)
RETURNS TABLE (class TEXT, lens TEXT)
LANGUAGE sql STABLE AS $$
    SELECT COALESCE(a.class, t.class)::TEXT,
           (CASE WHEN a.code IS NOT NULL THEN a.lens ELSE t.lens END)::TEXT
    FROM asset_types t
    LEFT JOIN asset_types a
           ON a.alias_of = t.code
          AND a.alias_sub_type = p_sub_type
    WHERE t.code = p_type
$$;

CREATE OR REPLACE FUNCTION assets_sync_registry_class()
RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    c RECORD;
BEGIN
    SELECT * INTO c FROM asset_type_classification(NEW.asset_type, NEW.sub_type);
    IF FOUND THEN
        NEW.asset_class := c.class;
        NEW.asset_lens := c.lens;
    ELSE
        NEW.asset_class := 'other';
        NEW.asset_lens := NULL;
    END IF;
    RETURN NEW;
END $$;

-- asset_class and asset_lens are in the column list so that a direct write
-- to them is re-derived: they never disagree with the type.
DROP TRIGGER IF EXISTS trg_assets_registry_class ON assets;
CREATE TRIGGER trg_assets_registry_class
    BEFORE INSERT OR UPDATE OF asset_type, sub_type, asset_class, asset_lens ON assets
    FOR EACH ROW EXECUTE FUNCTION assets_sync_registry_class();

-- One backfill batch: the next p_batch assets after p_after (by id) whose
-- class or lens is out of date are fixed. Returns the last id visited, or
-- NULL when there are no more rows. Re-runnable; a registry migration calls
-- it after re-seeding asset_types.
CREATE OR REPLACE FUNCTION asset_registry_backfill(p_after UUID, p_batch INT,
                                                   OUT last_id UUID, OUT updated INT)
LANGUAGE plpgsql AS $$
BEGIN
    SELECT page.id INTO last_id FROM (
        SELECT id FROM assets
        WHERE p_after IS NULL OR id > p_after
        ORDER BY id
        LIMIT p_batch
    ) page
    ORDER BY page.id DESC
    LIMIT 1;

    IF last_id IS NULL THEN
        updated := 0;
        RETURN;
    END IF;

    UPDATE assets a
       SET asset_class = COALESCE(c.class, 'other'),
           asset_lens = c.lens
      FROM assets b
      LEFT JOIN LATERAL asset_type_classification(b.asset_type, b.sub_type) c ON TRUE
     WHERE a.id = b.id
       AND (p_after IS NULL OR b.id > p_after)
       AND b.id <= last_id
       AND (a.asset_class IS DISTINCT FROM COALESCE(c.class, 'other')
            OR a.asset_lens IS DISTINCT FROM c.lens);
    GET DIAGNOSTICS updated = ROW_COUNT;
END $$;

-- BEGIN asset-type-registry (registry version 48862d766758d927)
-- Generated from api/configs/asset-types.yaml by `make asset-types-sql`.
-- Do not edit: `go run ./cmd/gen-asset-types -check` compares this block
-- with the YAML.
ALTER TABLE asset_types DROP CONSTRAINT IF EXISTS chk_asset_types_class;
ALTER TABLE asset_types ADD CONSTRAINT chk_asset_types_class CHECK (class IN ('domain', 'ip_address', 'certificate', 'service', 'web_endpoint', 'application', 'host', 'function', 'cloud_account', 'container', 'cluster', 'artifact_registry', 'code_repo', 'identity', 'data_store', 'network', 'other'));
ALTER TABLE asset_types DROP CONSTRAINT IF EXISTS chk_asset_types_lens;
ALTER TABLE asset_types ADD CONSTRAINT chk_asset_types_lens CHECK (lens IS NULL OR lens IN ('external_surface', 'applications', 'cloud_infra', 'containers_k8s', 'code', 'identities', 'data', 'network'));

INSERT INTO asset_types (code, name, class, lens, alias_of, alias_sub_type) VALUES
    ('domain', 'Domain', 'domain', 'external_surface', NULL, NULL),
    ('subdomain', 'Subdomain', 'domain', 'external_surface', NULL, NULL),
    ('ip_address', 'IP Address', 'ip_address', 'external_surface', NULL, NULL),
    ('certificate', 'Certificate', 'certificate', 'external_surface', NULL, NULL),
    ('service', 'Service', 'service', 'external_surface', NULL, NULL),
    ('http_service', 'HTTP Service', 'service', 'external_surface', 'service', 'http'),
    ('open_port', 'Open Port', 'service', 'external_surface', 'service', 'open_port'),
    ('discovered_url', 'Discovered URL', 'web_endpoint', 'external_surface', 'service', 'discovered_url'),
    ('application', 'Application', 'application', 'applications', NULL, NULL),
    ('website', 'Website', 'application', 'applications', 'application', 'website'),
    ('web_application', 'Web Application', 'application', 'applications', 'application', 'web_application'),
    ('api', 'API', 'application', 'applications', 'application', 'api'),
    ('mobile_app', 'Mobile App', 'application', 'applications', 'application', 'mobile_app'),
    ('host', 'Host', 'host', 'cloud_infra', NULL, NULL),
    ('compute', 'Compute Instance', 'host', 'cloud_infra', 'host', 'compute'),
    ('endpoint', 'Endpoint', 'host', 'cloud_infra', NULL, NULL),
    ('serverless', 'Serverless Function', 'function', 'cloud_infra', 'host', 'serverless'),
    ('cloud_account', 'Cloud Account', 'cloud_account', 'cloud_infra', NULL, NULL),
    ('container', 'Container', 'container', 'containers_k8s', NULL, NULL),
    ('kubernetes', 'Kubernetes', 'cluster', 'containers_k8s', NULL, NULL),
    ('kubernetes_cluster', 'Kubernetes Cluster', 'cluster', 'containers_k8s', 'kubernetes', 'cluster'),
    ('kubernetes_namespace', 'Kubernetes Namespace', 'cluster', 'containers_k8s', 'kubernetes', 'namespace'),
    ('container_registry', 'Container Registry', 'artifact_registry', 'containers_k8s', 'storage', 'container_registry'),
    ('repository', 'Repository', 'code_repo', 'code', NULL, NULL),
    ('identity', 'Identity', 'identity', 'identities', NULL, NULL),
    ('iam_user', 'IAM User', 'identity', 'identities', 'identity', 'iam_user'),
    ('iam_role', 'IAM Role', 'identity', 'identities', 'identity', 'iam_role'),
    ('service_account', 'Service Account', 'identity', 'identities', 'identity', 'service_account'),
    ('database', 'Database', 'data_store', 'data', NULL, NULL),
    ('data_store', 'Data Store', 'data_store', 'data', 'database', 'data_store'),
    ('storage', 'Storage', 'data_store', 'data', NULL, NULL),
    ('s3_bucket', 'S3 Bucket', 'data_store', 'data', 'storage', 's3_bucket'),
    ('network', 'Network', 'network', 'network', NULL, NULL),
    ('vpc', 'VPC', 'network', 'network', 'network', 'vpc'),
    ('subnet', 'Subnet', 'network', 'network', 'network', 'subnet'),
    ('firewall', 'Firewall', 'network', 'network', 'network', 'firewall'),
    ('load_balancer', 'Load Balancer', 'network', 'network', 'network', 'load_balancer'),
    ('unclassified', 'Unclassified', 'other', NULL, NULL, NULL)
ON CONFLICT (code) DO UPDATE SET
    class = EXCLUDED.class,
    lens = EXCLUDED.lens,
    alias_of = EXCLUDED.alias_of,
    alias_sub_type = EXCLUDED.alias_sub_type;

-- Codes that are not registry types (legacy rows kept for the assets FK).
UPDATE asset_types SET class = 'other', lens = NULL, alias_of = NULL, alias_sub_type = NULL
WHERE code NOT IN ('domain', 'subdomain', 'ip_address', 'certificate', 'service', 'http_service', 'open_port', 'discovered_url', 'application', 'website', 'web_application', 'api', 'mobile_app', 'host', 'compute', 'endpoint', 'serverless', 'cloud_account', 'container', 'kubernetes', 'kubernetes_cluster', 'kubernetes_namespace', 'container_registry', 'repository', 'identity', 'iam_user', 'iam_role', 'service_account', 'database', 'data_store', 'storage', 's3_bucket', 'network', 'vpc', 'subnet', 'firewall', 'load_balancer', 'unclassified');

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
-- END asset-type-registry
