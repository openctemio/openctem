-- Set-valued asset attributes reconciled per source (RFC-069 §13): each
-- source keeps its own record of every IP address, technology and open port
-- it reported, with when it last saw it. An element leaves a source's
-- contribution only when the same source observes the same coverage again
-- without it (removed_at); the asset shows the union of the trusted, fresh
-- sources. New table, no backfill: existing values are kept as they are
-- until a source that covers them reports.
CREATE TABLE asset_attribute_set_elements (
    tenant_id    UUID         NOT NULL,
    asset_id     UUID         NOT NULL,
    attribute    VARCHAR(40)  NOT NULL,
    source_kind  VARCHAR(20)  NOT NULL,
    source_name  VARCHAR(100) NOT NULL DEFAULT '',
    element      VARCHAR(200) NOT NULL,
    coverage_key VARCHAR(200) NOT NULL DEFAULT '',
    first_seen   TIMESTAMPTZ  NOT NULL,
    last_seen    TIMESTAMPTZ  NOT NULL,
    removed_at   TIMESTAMPTZ,
    source_run   VARCHAR(100) NOT NULL DEFAULT '',
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_attribute_set_elements
        PRIMARY KEY (tenant_id, asset_id, attribute, source_kind, source_name, element),
    CONSTRAINT fk_asset_attribute_set_elements_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_attribute_set_elements_attribute
        CHECK (attribute IN ('ip_addresses', 'technologies', 'open_ports')),
    CONSTRAINT chk_asset_attribute_set_elements_kind
        CHECK (source_kind IN ('manual', 'integration', 'import', 'scan', 'feed')),
    CONSTRAINT chk_asset_attribute_set_elements_seen CHECK (first_seen <= last_seen)
);
COMMENT ON TABLE asset_attribute_set_elements IS
    'RFC-069: per-source elements of set-valued asset attributes (ip_addresses, technologies, open_ports). removed_at: the same source observed the coverage without the element.';

-- Retention and the daily TTL sweep scan by tenant and age.
CREATE INDEX idx_asset_attribute_set_elements_seen
    ON asset_attribute_set_elements (tenant_id, last_seen);
