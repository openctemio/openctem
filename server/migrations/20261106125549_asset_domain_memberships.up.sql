-- Domain membership of assets (api/docs/architecture/asset-domain-membership.md).
--
-- The findings filter asset_domain=x reaches every asset that belongs to x:
-- names, the addresses those names resolve to (never a CDN or shared front
-- end), services on those hosts, certificates naming x, web applications
-- and other assets with a DNS name. Which names an asset belongs to is
-- derived in Go (pkg/domain/assetdomain) and stored here as keys, so the
-- filter is one index lookup.
--
-- Keys of an asset named api.example.com: "api.example.com" (the name) and
-- "*.example.com" (every parent down to the registrable domain). The filter
-- "example.com" matches the keys example.com and *.example.com; "*.example.com"
-- matches *.example.com only.
--
-- Triggers queue every asset whose name, type, name-bearing properties or
-- edges change in asset_domain_queue, so no write path can forget it; the
-- asset-domain-membership worker drains the queue in batches and also
-- refreshes the assets that depend on a changed one (the addresses a name
-- resolves to, the services on them).
--
-- Live impact: two new tables, AFTER triggers on assets and
-- asset_relationships that insert into the queue only, and every live asset
-- queued once at the end (the worker fills the table in the background
-- after deploy). No existing row changes. Safe to rerun.

CREATE TABLE IF NOT EXISTS asset_domain_memberships (
    tenant_id uuid NOT NULL,
    asset_id  uuid NOT NULL,
    key       text NOT NULL,
    CONSTRAINT pk_asset_domain_memberships PRIMARY KEY (tenant_id, key, asset_id),
    CONSTRAINT fk_asset_domain_memberships_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_domain_memberships_key CHECK (length(key) BETWEEN 1 AND 255)
);

-- The refresh replaces one asset's rows.
CREATE INDEX IF NOT EXISTS idx_asset_domain_memberships_asset ON asset_domain_memberships (tenant_id, asset_id);

COMMENT ON TABLE asset_domain_memberships IS
    'DNS names each asset belongs to, as filter keys (name, and *.parent down to the registrable domain); written only by the asset-domain-membership worker.';

CREATE TABLE IF NOT EXISTS asset_domain_queue (
    asset_id    uuid        NOT NULL,
    tenant_id   uuid        NOT NULL,
    enqueued_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_domain_queue PRIMARY KEY (asset_id),
    CONSTRAINT fk_asset_domain_queue_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_domain_queue_enqueued ON asset_domain_queue (enqueued_at);

COMMENT ON TABLE asset_domain_queue IS
    'Assets whose domain membership must be recomputed by the asset-domain-membership worker; one row per asset.';

-- New assets (statement level, transition table new_assets).
CREATE OR REPLACE FUNCTION asset_domain_enqueue_new_assets() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_domain_queue (asset_id, tenant_id)
    SELECT n.id, n.tenant_id FROM new_assets n
    ORDER BY n.id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

-- One updated asset whose name-bearing columns changed.
CREATE OR REPLACE FUNCTION asset_domain_enqueue_asset() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_domain_queue (asset_id, tenant_id)
    VALUES (NEW.id, NEW.tenant_id)
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

-- Both ends of changed edges (transition table changed_rows), the ones that
-- membership follows only, and only ends that still exist (a cascaded edge
-- delete fires while its asset is being deleted).
CREATE OR REPLACE FUNCTION asset_domain_enqueue_edges() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_domain_queue (asset_id, tenant_id)
    SELECT DISTINCT a.id, a.tenant_id
    FROM changed_rows c
    JOIN assets a ON a.tenant_id = c.tenant_id AND a.id IN (c.source_asset_id, c.target_asset_id)
    WHERE c.relationship_type IN ('resolves_to', 'exposes', 'runs_on')
    ORDER BY a.id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_assets_domain_insert ON assets;
CREATE TRIGGER trg_assets_domain_insert
    AFTER INSERT ON assets
    REFERENCING NEW TABLE AS new_assets
    FOR EACH STATEMENT EXECUTE FUNCTION asset_domain_enqueue_new_assets();

-- The property keys are the ones pkg/domain/assetdomain reads.
DROP TRIGGER IF EXISTS trg_assets_domain_update ON assets;
CREATE TRIGGER trg_assets_domain_update
    AFTER UPDATE OF name, asset_type, properties, deleted_at ON assets
    FOR EACH ROW
    WHEN (OLD.name IS DISTINCT FROM NEW.name
       OR OLD.asset_type IS DISTINCT FROM NEW.asset_type
       OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
       OR (OLD.properties -> 'hostname') IS DISTINCT FROM (NEW.properties -> 'hostname')
       OR (OLD.properties -> 'fqdn') IS DISTINCT FROM (NEW.properties -> 'fqdn')
       OR (OLD.properties -> 'subject_cn') IS DISTINCT FROM (NEW.properties -> 'subject_cn')
       OR (OLD.properties -> 'sans') IS DISTINCT FROM (NEW.properties -> 'sans')
       OR (OLD.properties -> 'san') IS DISTINCT FROM (NEW.properties -> 'san')
       OR (OLD.properties -> 'url') IS DISTINCT FROM (NEW.properties -> 'url')
       OR (OLD.properties -> 'base_url') IS DISTINCT FROM (NEW.properties -> 'base_url')
       OR (OLD.properties -> 'host') IS DISTINCT FROM (NEW.properties -> 'host')
       OR (OLD.properties -> 'dns_name') IS DISTINCT FROM (NEW.properties -> 'dns_name')
       OR (OLD.properties -> 'endpoint') IS DISTINCT FROM (NEW.properties -> 'endpoint')
       OR (OLD.properties -> 'cdn') IS DISTINCT FROM (NEW.properties -> 'cdn')
       OR (OLD.properties -> 'asn_org') IS DISTINCT FROM (NEW.properties -> 'asn_org'))
    EXECUTE FUNCTION asset_domain_enqueue_asset();

DROP TRIGGER IF EXISTS trg_asset_relationships_domain_insert ON asset_relationships;
CREATE TRIGGER trg_asset_relationships_domain_insert
    AFTER INSERT ON asset_relationships
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_domain_enqueue_edges();

DROP TRIGGER IF EXISTS trg_asset_relationships_domain_delete ON asset_relationships;
CREATE TRIGGER trg_asset_relationships_domain_delete
    AFTER DELETE ON asset_relationships
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_domain_enqueue_edges();

-- An edge repointed by a merge or retyped: both ends, old and new. A
-- refresh of last_verified does not fire it.
CREATE OR REPLACE FUNCTION asset_domain_enqueue_edge_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_domain_queue (asset_id, tenant_id)
    SELECT DISTINCT a.id, a.tenant_id FROM assets a
    WHERE a.tenant_id IN (OLD.tenant_id, NEW.tenant_id)
      AND a.id IN (OLD.source_asset_id, OLD.target_asset_id, NEW.source_asset_id, NEW.target_asset_id)
    ORDER BY a.id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_asset_relationships_domain_update ON asset_relationships;
CREATE TRIGGER trg_asset_relationships_domain_update
    AFTER UPDATE OF source_asset_id, target_asset_id, relationship_type ON asset_relationships
    FOR EACH ROW
    WHEN (OLD.source_asset_id IS DISTINCT FROM NEW.source_asset_id
       OR OLD.target_asset_id IS DISTINCT FROM NEW.target_asset_id
       OR OLD.relationship_type IS DISTINCT FROM NEW.relationship_type)
    EXECUTE FUNCTION asset_domain_enqueue_edge_update();

-- Backfill: queue every live asset once (data-adding only, rerunnable).
INSERT INTO asset_domain_queue (asset_id, tenant_id)
SELECT a.id, a.tenant_id FROM assets a
WHERE a.deleted_at IS NULL
ORDER BY a.id
ON CONFLICT (asset_id) DO NOTHING;
