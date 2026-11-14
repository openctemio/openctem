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
-- Live impact: a new empty table, functions, a procedure and AFTER triggers
-- on assets. No existing row is read or changed here. Creating the foreign
-- key and the triggers takes a SHARE ROW EXCLUSIVE lock on assets for a few
-- milliseconds (it waits for running writes to assets and holds new ones
-- back while it waits). From the commit on, every write keeps the table in
-- step; the rows of the existing assets are copied by the next migration,
-- 20261114055218_asset_ip_addresses_backfill, in short batches that never
-- block writes to assets.

-- The addresses of an asset. A SQL-standard body (BEGIN ATOMIC) is parsed
-- when the function is created: every name in it is bound then (and every
-- one is schema-qualified as well), so the caller's search_path cannot
-- change what it calls. It has no SET clause, so the planner inlines it into
-- the calling statement (the backfill, the triggers, asset merges): a SET
-- clause would make it a separate function call per asset, about three
-- times slower. It is not SECURITY DEFINER and runs with the caller's
-- rights.
CREATE OR REPLACE FUNCTION public.asset_recorded_addresses(asset_type text, name text, properties jsonb)
    RETURNS SETOF inet
    LANGUAGE sql IMMUTABLE PARALLEL SAFE
BEGIN ATOMIC
    SELECT DISTINCT s.addr FROM (
        SELECT public.parse_asset_ip(name) AS addr
        WHERE asset_type OPERATOR(pg_catalog.=) ANY (ARRAY['ip_address', 'host']::pg_catalog.text[])
        UNION ALL
        SELECT public.parse_asset_ip(e.v)
        FROM pg_catalog.jsonb_array_elements_text(
            CASE pg_catalog.jsonb_typeof(properties OPERATOR(pg_catalog.->) 'ip_addresses')
                WHEN 'array' THEN properties OPERATOR(pg_catalog.->) 'ip_addresses'
                WHEN 'string' THEN pg_catalog.jsonb_build_array(properties OPERATOR(pg_catalog.->) 'ip_addresses')
                ELSE '[]'::pg_catalog.jsonb
            END) AS e(v)
        WHERE asset_type OPERATOR(pg_catalog.=) ANY (ARRAY['host', 'network', 'compute', 'endpoint', 'firewall', 'load_balancer']::pg_catalog.text[])
        UNION ALL
        SELECT public.parse_asset_ip(properties OPERATOR(pg_catalog.->>) k.key)
        FROM pg_catalog.unnest(ARRAY['private_ip', 'public_ip']::pg_catalog.text[]) AS k(key)
        WHERE asset_type OPERATOR(pg_catalog.=) ANY (ARRAY['host', 'network', 'compute', 'endpoint', 'firewall', 'load_balancer']::pg_catalog.text[])
          AND pg_catalog.jsonb_typeof(properties OPERATOR(pg_catalog.->) k.key) OPERATOR(pg_catalog.=) 'string'
    ) s
    WHERE s.addr IS NOT NULL;
END;

COMMENT ON FUNCTION public.asset_recorded_addresses(text, text, jsonb) IS
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

-- The tenant isolation policy every tenant table carries (row level security
-- runs in shadow mode: the policy is defined, the queries filter on
-- tenant_id).
CREATE POLICY asset_ip_addresses_tenant_isolation ON asset_ip_addresses
    USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)
        OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));

COMMENT ON TABLE asset_ip_addresses IS
    'IP addresses of each live asset (asset_recorded_addresses), for the address range filters; written only by the triggers on assets, asset merges and the one-off backfill.';

-- New assets (statement level, transition table new_assets).
CREATE OR REPLACE FUNCTION public.asset_ip_addresses_insert() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public
AS $$
BEGIN
    INSERT INTO public.asset_ip_addresses (tenant_id, asset_id, addr)
    SELECT n.tenant_id, n.id, r.addr
    FROM new_assets n
    CROSS JOIN LATERAL public.asset_recorded_addresses(n.asset_type, n.name, n.properties) AS r(addr)
    WHERE n.deleted_at IS NULL
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END;
$$;

-- One updated asset whose addresses may have changed: its rows are replaced
-- (none while it is deleted).
CREATE OR REPLACE FUNCTION public.asset_ip_addresses_update() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, public
AS $$
BEGIN
    DELETE FROM public.asset_ip_addresses WHERE tenant_id = OLD.tenant_id AND asset_id = OLD.id;
    IF NEW.deleted_at IS NULL THEN
        INSERT INTO public.asset_ip_addresses (tenant_id, asset_id, addr)
        SELECT NEW.tenant_id, NEW.id, r.addr
        FROM public.asset_recorded_addresses(NEW.asset_type, NEW.name, NEW.properties) AS r(addr)
        ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_assets_ip_addresses_insert ON assets;
CREATE TRIGGER trg_assets_ip_addresses_insert
    AFTER INSERT ON assets
    REFERENCING NEW TABLE AS new_assets
    FOR EACH STATEMENT EXECUTE FUNCTION public.asset_ip_addresses_insert();

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
    EXECUTE FUNCTION public.asset_ip_addresses_update();

-- Copies the addresses of the assets that existed before the triggers, in
-- batches of batch_size assets by id, each its own transaction, so writes to
-- assets are never blocked for long: a batch holds a FOR SHARE lock on its
-- own rows only for the batch (a writer of one of them waits for that
-- batch, a writer of any other asset does not wait at all).
--
-- Concurrent writes stay exact:
-- - a batch locks its rows, so it reads each asset's current row (one
--   updated since the statement began is re-read after the writer's
--   commit) and no writer changes it until the batch commits; after that,
--   the triggers keep the asset's rows in step;
-- - a row another transaction holds locked is skipped (SKIP LOCKED, so a
--   batch never waits on a writer and cannot deadlock with one) and copied
--   once more at the end, waiting for the writer this time (the reconcile
--   pass);
-- - only inserts, ON CONFLICT DO NOTHING: rows a trigger wrote meanwhile are
--   kept, and running it again changes nothing.
--
-- Transaction control (COMMIT) is only allowed when the procedure is CALLed
-- outside a transaction block, so it has no SET clause and every name in it
-- is schema-qualified; it runs with the caller's rights. CALL it as the only
-- statement of a migration file (or of a psql command).
CREATE OR REPLACE PROCEDURE public.asset_ip_addresses_backfill(batch_size integer DEFAULT 2000)
    LANGUAGE plpgsql
AS $$
DECLARE
    last_id uuid := '00000000-0000-0000-0000-000000000000';
    next_id uuid;
    skipped uuid[] := '{}';
    batch_skipped uuid[];
    copied bigint := 0;
    batch_rows bigint;
    skipped_id uuid;
BEGIN
    IF batch_size IS NULL OR batch_size < 1 OR batch_size > 100000 THEN
        RAISE EXCEPTION 'asset_ip_addresses_backfill: batch_size must be between 1 and 100000';
    END IF;

    LOOP
        SELECT s.id INTO next_id
        FROM (SELECT a.id FROM public.assets a WHERE a.id > last_id ORDER BY a.id LIMIT batch_size) s
        ORDER BY s.id DESC LIMIT 1;
        EXIT WHEN next_id IS NULL;

        WITH locked AS MATERIALIZED (
            SELECT a.id, a.tenant_id, a.asset_type, a.name, a.properties
            FROM public.assets a
            WHERE a.id > last_id AND a.id <= next_id AND a.deleted_at IS NULL
            FOR SHARE OF a SKIP LOCKED
        ), added AS (
            INSERT INTO public.asset_ip_addresses (tenant_id, asset_id, addr)
            SELECT l.tenant_id, l.id, r.addr
            FROM locked l
            CROSS JOIN LATERAL public.asset_recorded_addresses(l.asset_type, l.name, l.properties) AS r(addr)
            ON CONFLICT DO NOTHING
            RETURNING 1
        )
        SELECT (SELECT pg_catalog.count(*) FROM added),
               (SELECT COALESCE(pg_catalog.array_agg(a.id), '{}'::uuid[])
                FROM public.assets a
                WHERE a.id > last_id AND a.id <= next_id AND a.deleted_at IS NULL
                  AND NOT EXISTS (SELECT 1 FROM locked l WHERE l.id = a.id))
        INTO batch_rows, batch_skipped;

        copied := copied + batch_rows;
        skipped := skipped || batch_skipped;
        last_id := next_id;
        COMMIT;
    END LOOP;

    -- Reconcile: the assets a writer held while their batch ran, now read
    -- after that writer (FOR SHARE waits for it). One asset per transaction:
    -- it never holds one row while it waits for another, so it cannot be
    -- part of a deadlock.
    FOREACH skipped_id IN ARRAY skipped LOOP
        WITH locked AS MATERIALIZED (
            SELECT a.id, a.tenant_id, a.asset_type, a.name, a.properties
            FROM public.assets a
            WHERE a.id = skipped_id AND a.deleted_at IS NULL
            FOR SHARE OF a
        )
        INSERT INTO public.asset_ip_addresses (tenant_id, asset_id, addr)
        SELECT l.tenant_id, l.id, r.addr
        FROM locked l
        CROSS JOIN LATERAL public.asset_recorded_addresses(l.asset_type, l.name, l.properties) AS r(addr)
        ON CONFLICT DO NOTHING;
        GET DIAGNOSTICS batch_rows = ROW_COUNT;
        copied := copied + batch_rows;
        COMMIT;
    END LOOP;

    ANALYZE public.asset_ip_addresses;
    RAISE NOTICE 'asset_ip_addresses_backfill: % address rows copied, % assets reconciled after a concurrent write',
        copied, COALESCE(pg_catalog.cardinality(skipped), 0);
END;
$$;

REVOKE ALL ON PROCEDURE public.asset_ip_addresses_backfill(integer) FROM PUBLIC;
