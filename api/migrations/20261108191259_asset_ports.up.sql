-- Open ports of assets, for the port and service filters of the asset list
-- (port=443, service=ssh) and the Open ports column of the IP addresses tab
-- (docs/architecture/list-query-contract.md, "Asset inventory").
--
-- A port scan stores each open port as a service asset (sub_type open_port)
-- that its address exposes (ip_address -exposes-> service). This table
-- lists, per asset, the ports it answers on, so the filter is one index
-- lookup instead of a walk over edges and properties:
--   - the open_port service itself;
--   - the address (or host) that exposes it;
--   - every name that resolves to that address (one hop).
-- Rows are derived and written only by the asset-ports worker: AFTER triggers
-- queue every asset whose port facts or edges change, the worker recomputes
-- the rows of the queued assets and of the assets that depend on them.
--
-- Live impact: two new tables; AFTER triggers on assets and
-- asset_relationships that insert into the queue only; every live address,
-- host and open_port service queued once at the end (the worker fills the
-- table in the background after deploy). No existing row changes.

CREATE TABLE IF NOT EXISTS asset_ports (
    tenant_id     uuid    NOT NULL,
    asset_id      uuid    NOT NULL,
    port_asset_id uuid    NOT NULL,
    port          integer NOT NULL,
    transport     text    NOT NULL DEFAULT '',
    service       text    NOT NULL DEFAULT '',
    CONSTRAINT pk_asset_ports PRIMARY KEY (tenant_id, asset_id, port_asset_id),
    CONSTRAINT fk_asset_ports_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_ports_port_asset FOREIGN KEY (tenant_id, port_asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_ports_port CHECK (port BETWEEN 0 AND 65535),
    CONSTRAINT chk_asset_ports_transport CHECK (transport IN ('', 'tcp', 'udp', 'sctp')),
    CONSTRAINT chk_asset_ports_service CHECK (length(service) <= 64)
);

-- port=443: the assets of a tenant on a port.
CREATE INDEX IF NOT EXISTS idx_asset_ports_port ON asset_ports (tenant_id, port, asset_id);
-- service=ssh.
CREATE INDEX IF NOT EXISTS idx_asset_ports_service ON asset_ports (tenant_id, service, asset_id) WHERE service <> '';
-- The refresh and the list column read one asset's rows.
CREATE INDEX IF NOT EXISTS idx_asset_ports_port_asset ON asset_ports (tenant_id, port_asset_id);

COMMENT ON TABLE asset_ports IS
    'Open ports each asset answers on (the open_port service, its address, names resolving to the address); written only by the asset-ports worker.';

CREATE TABLE IF NOT EXISTS asset_port_queue (
    asset_id    uuid        NOT NULL,
    tenant_id   uuid        NOT NULL,
    enqueued_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_port_queue PRIMARY KEY (asset_id),
    CONSTRAINT fk_asset_port_queue_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_asset_port_queue_enqueued ON asset_port_queue (enqueued_at);

COMMENT ON TABLE asset_port_queue IS
    'Assets whose open ports must be recomputed by the asset-ports worker; one row per asset.';

-- New port-bearing assets (statement level).
CREATE OR REPLACE FUNCTION asset_ports_enqueue_new_assets() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_port_queue (asset_id, tenant_id)
    SELECT n.id, n.tenant_id FROM new_assets n
    WHERE n.asset_type = 'service'
    ORDER BY n.id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION asset_ports_enqueue_asset() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_port_queue (asset_id, tenant_id)
    VALUES (NEW.id, NEW.tenant_id)
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

-- Both ends of changed exposes / resolves_to edges that still exist.
CREATE OR REPLACE FUNCTION asset_ports_enqueue_edges() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO asset_port_queue (asset_id, tenant_id)
    SELECT DISTINCT a.id, a.tenant_id
    FROM changed_rows c
    JOIN assets a ON a.tenant_id = c.tenant_id AND a.id IN (c.source_asset_id, c.target_asset_id)
    WHERE c.relationship_type IN ('exposes', 'resolves_to')
    ORDER BY a.id
    ON CONFLICT (asset_id) DO NOTHING;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_assets_ports_insert ON assets;
CREATE TRIGGER trg_assets_ports_insert
    AFTER INSERT ON assets
    REFERENCING NEW TABLE AS new_assets
    FOR EACH STATEMENT EXECUTE FUNCTION asset_ports_enqueue_new_assets();

DROP TRIGGER IF EXISTS trg_assets_ports_update ON assets;
CREATE TRIGGER trg_assets_ports_update
    AFTER UPDATE OF asset_type, sub_type, status, deleted_at, properties ON assets
    FOR EACH ROW
    WHEN (NEW.asset_type IN ('service', 'ip_address', 'host') AND (
          OLD.asset_type IS DISTINCT FROM NEW.asset_type
       OR OLD.sub_type IS DISTINCT FROM NEW.sub_type
       OR OLD.status IS DISTINCT FROM NEW.status
       OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at
       OR (OLD.properties -> 'port') IS DISTINCT FROM (NEW.properties -> 'port')
       OR (OLD.properties -> 'transport') IS DISTINCT FROM (NEW.properties -> 'transport')
       OR (OLD.properties -> 'protocol') IS DISTINCT FROM (NEW.properties -> 'protocol')
       OR (OLD.properties -> 'service') IS DISTINCT FROM (NEW.properties -> 'service')
       OR (OLD.properties -> 'name') IS DISTINCT FROM (NEW.properties -> 'name')))
    EXECUTE FUNCTION asset_ports_enqueue_asset();

DROP TRIGGER IF EXISTS trg_asset_relationships_ports_insert ON asset_relationships;
CREATE TRIGGER trg_asset_relationships_ports_insert
    AFTER INSERT ON asset_relationships
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_ports_enqueue_edges();

DROP TRIGGER IF EXISTS trg_asset_relationships_ports_update ON asset_relationships;
CREATE TRIGGER trg_asset_relationships_ports_update
    AFTER UPDATE ON asset_relationships
    REFERENCING NEW TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_ports_enqueue_edges();

DROP TRIGGER IF EXISTS trg_asset_relationships_ports_delete ON asset_relationships;
CREATE TRIGGER trg_asset_relationships_ports_delete
    AFTER DELETE ON asset_relationships
    REFERENCING OLD TABLE AS changed_rows
    FOR EACH STATEMENT EXECUTE FUNCTION asset_ports_enqueue_edges();

-- Backfill: every live open_port service once; the worker derives its
-- address and the names resolving to it.
INSERT INTO asset_port_queue (asset_id, tenant_id)
SELECT a.id, a.tenant_id FROM assets a
WHERE a.asset_type = 'service' AND a.deleted_at IS NULL
ORDER BY a.id
ON CONFLICT (asset_id) DO NOTHING;
