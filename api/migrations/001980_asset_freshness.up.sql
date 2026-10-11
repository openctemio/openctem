-- Asset freshness (docs/rfcs/RFC-075-asset-freshness.md): when each
-- enrichable attribute class of an asset (DNS, registration, network owner,
-- HTTP, TLS, ports) was last observed, and by which tool. Written by ingest
-- for every asset a report wrote; read for the asset's freshness panel and
-- the inventory's stale filter.
--
-- Live impact: a new, empty table. Existing assets show their passive
-- classes as never observed until a report or an enrichment run observes
-- them.

CREATE TABLE IF NOT EXISTS asset_attribute_freshness (
    tenant_id   uuid         NOT NULL,
    asset_id    uuid         NOT NULL,
    class       varchar(30)  NOT NULL,
    observed_at timestamptz  NOT NULL,
    source      varchar(100) NOT NULL DEFAULT '',
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_attribute_freshness PRIMARY KEY (tenant_id, asset_id, class),
    CONSTRAINT fk_asset_attribute_freshness_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_attribute_freshness_class
        CHECK (class IN ('dns', 'registration', 'network_owner', 'http', 'tls', 'ports')),
    CONSTRAINT chk_asset_attribute_freshness_observed CHECK (observed_at <= updated_at + interval '1 minute')
);

COMMENT ON TABLE asset_attribute_freshness IS
    'RFC-075: last observation of each enrichable attribute class of an asset, for freshness (live, stale, dead).';

-- The stale filter and the staleness picker read by class and age.
CREATE INDEX IF NOT EXISTS idx_asset_attribute_freshness_class_observed
    ON asset_attribute_freshness (tenant_id, class, observed_at);
