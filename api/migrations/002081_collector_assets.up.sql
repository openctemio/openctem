-- Complete reports from trusted collectors (RFC-040 §12): which assets each
-- collector source (sensor, tool and collector instance) reported, whether
-- that source created the asset, when it last reported it, and since when a
-- complete report of the source no longer lists it. Only an asset its own
-- collector source created may be changed by that source's complete reports
-- and marked not seen by them; nothing here ever deletes an asset.
--
-- Live impact: a new, empty table. Assets collectors created before this
-- migration have no row, so no collector changes or marks them until it
-- creates them again.

CREATE TABLE IF NOT EXISTS collector_assets (
    tenant_id     uuid         NOT NULL,
    sensor_id     uuid         NOT NULL,
    tool          varchar(100) NOT NULL,
    source_ref    varchar(255) NOT NULL DEFAULT '',
    asset_id      uuid         NOT NULL,
    created_asset boolean      NOT NULL DEFAULT false,
    first_seen    timestamptz  NOT NULL,
    last_seen     timestamptz  NOT NULL,
    missing_since timestamptz,
    CONSTRAINT pk_collector_assets PRIMARY KEY (tenant_id, sensor_id, tool, source_ref, asset_id),
    CONSTRAINT fk_collector_assets_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_collector_assets_sensor FOREIGN KEY (tenant_id, sensor_id)
        REFERENCES sensors (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_collector_assets_seen CHECK (first_seen <= last_seen)
);

COMMENT ON TABLE collector_assets IS
    'RFC-040 §12: assets a trusted collector source reported; created_asset marks the ones it may change and mark not seen.';

-- The asset side (cascade, "which collectors report this asset").
CREATE INDEX IF NOT EXISTS idx_collector_assets_asset ON collector_assets (tenant_id, asset_id);
