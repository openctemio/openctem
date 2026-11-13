-- The IP addresses each asset has, for the address range filters: the assets
-- ip filter, the findings asset_ip filter, smart asset group rules (in_cidr)
-- and the query language's asset.ip (docs/architecture/asset-addresses.md).
--
-- An asset's addresses are its name when it is an address (ip_address, and a
-- host named by an address) and, for machines (host and network devices),
-- every address recorded in its properties: ip_addresses (the union of the
-- current per-source addresses, kept by attribute reconciliation),
-- private_ip and public_ip. A domain's or a service's ip_addresses are what
-- the name resolves to or listens on, not addresses the asset has, and are
-- not here.
--
-- A range filter is one btree range scan per range on (tenant_id, addr):
-- stored addresses are full-mask, so "addr BETWEEN the first and the last
-- address of the range" is exact. Triggers keep the table in step with every
-- write to assets, whatever the write path.
--
-- Live impact: a new table, a function, AFTER triggers on assets, and every
-- live asset's addresses copied into the new table once, in this
-- transaction. No existing row changes. Creating the triggers blocks writes
-- to assets (not reads) until the copy commits: about a second per hundred
-- thousand assets.

CREATE OR REPLACE FUNCTION asset_recorded_addresses(asset_type text, name text, properties jsonb) RETURNS SETOF inet
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
    SET search_path = pg_catalog, public
AS $$
    SELECT DISTINCT s.addr FROM (
        SELECT parse_asset_ip(name) AS addr
        WHERE asset_type IN ('ip_address', 'host')
        UNION ALL
        SELECT parse_asset_ip(e.v)
        FROM jsonb_array_elements_text(
            CASE jsonb_typeof(properties -> 'ip_addresses')
                WHEN 'array' THEN properties -> 'ip_addresses'
                WHEN 'string' THEN jsonb_build_array(properties -> 'ip_addresses')
                ELSE '[]'::jsonb
            END) AS e(v)
        WHERE asset_type IN ('host', 'network', 'compute', 'endpoint', 'firewall', 'load_balancer')
        UNION ALL
        SELECT parse_asset_ip(properties ->> k.key)
        FROM unnest(ARRAY['private_ip', 'public_ip']) AS k(key)
        WHERE asset_type IN ('host', 'network', 'compute', 'endpoint', 'firewall', 'load_balancer')
          AND jsonb_typeof(properties -> k.key) = 'string'
    ) s
    WHERE s.addr IS NOT NULL
$$;

COMMENT ON FUNCTION asset_recorded_addresses(text, text, jsonb) IS
    'The addresses of an asset: its name when it is an address (ip_address, host), and for host and network devices the addresses in properties ip_addresses, private_ip and public_ip. Feeds asset_ip_addresses.';

CREATE TABLE IF NOT EXISTS asset_ip_addresses (
    tenant_id uuid NOT NULL,
    asset_id  uuid NOT NULL,
    addr      inet NOT NULL,
    CONSTRAINT pk_asset_ip_addresses PRIMARY KEY (tenant_id, asset_id, addr),
    CONSTRAINT fk_asset_ip_addresses_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);

-- The range filter: tenant first, then a btree range over the address.
CREATE INDEX IF NOT EXISTS idx_asset_ip_addresses_range ON asset_ip_addresses (tenant_id, addr);

COMMENT ON TABLE asset_ip_addresses IS
    'IP addresses of each live asset (asset_recorded_addresses), for the address range filters; written only by the triggers on assets.';

-- New assets (statement level, transition table new_assets).
CREATE OR REPLACE FUNCTION asset_ip_addresses_insert() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO asset_ip_addresses (tenant_id, asset_id, addr)
    SELECT n.tenant_id, n.id, r.addr
    FROM new_assets n
    CROSS JOIN LATERAL asset_recorded_addresses(n.asset_type, n.name, n.properties) AS r(addr)
    WHERE n.deleted_at IS NULL
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END;
$$;

-- One updated asset whose addresses may have changed: its rows are replaced
-- (none while it is deleted).
CREATE OR REPLACE FUNCTION asset_ip_addresses_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public
AS $$
BEGIN
    DELETE FROM asset_ip_addresses WHERE tenant_id = OLD.tenant_id AND asset_id = OLD.id;
    IF NEW.deleted_at IS NULL THEN
        INSERT INTO asset_ip_addresses (tenant_id, asset_id, addr)
        SELECT NEW.tenant_id, NEW.id, r.addr
        FROM asset_recorded_addresses(NEW.asset_type, NEW.name, NEW.properties) AS r(addr)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_assets_ip_addresses_insert ON assets;
CREATE TRIGGER trg_assets_ip_addresses_insert
    AFTER INSERT ON assets
    REFERENCING NEW TABLE AS new_assets
    FOR EACH STATEMENT EXECUTE FUNCTION asset_ip_addresses_insert();

-- The columns and property keys asset_recorded_addresses reads.
DROP TRIGGER IF EXISTS trg_assets_ip_addresses_update ON assets;
CREATE TRIGGER trg_assets_ip_addresses_update
    AFTER UPDATE OF name, asset_type, properties, deleted_at ON assets
    FOR EACH ROW
    WHEN (OLD.name IS DISTINCT FROM NEW.name
       OR OLD.asset_type IS DISTINCT FROM NEW.asset_type
       OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
       OR (OLD.properties -> 'ip_addresses') IS DISTINCT FROM (NEW.properties -> 'ip_addresses')
       OR (OLD.properties -> 'private_ip') IS DISTINCT FROM (NEW.properties -> 'private_ip')
       OR (OLD.properties -> 'public_ip') IS DISTINCT FROM (NEW.properties -> 'public_ip'))
    EXECUTE FUNCTION asset_ip_addresses_update();

-- The live assets' addresses, once.
INSERT INTO asset_ip_addresses (tenant_id, asset_id, addr)
SELECT a.tenant_id, a.id, r.addr
FROM assets a
CROSS JOIN LATERAL asset_recorded_addresses(a.asset_type, a.name, a.properties) AS r(addr)
WHERE a.deleted_at IS NULL
ON CONFLICT DO NOTHING;
