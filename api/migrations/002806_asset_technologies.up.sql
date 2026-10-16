-- Asset technologies (RFC-112): every technology a fingerprinting probe
-- detected on an asset, with a category from a closed set, an optional
-- version, the tool's confidence and when it was first and last seen. One
-- row per asset and normalised name. The rows follow the asset's reconciled
-- properties.technologies: when set reconciliation drops a technology from
-- the asset, its row is deleted in the same transaction.
--
-- New, empty table: no lock on any existing table beyond the foreign key's
-- share lock while the constraint is added. Existing assets are filled by
-- the asset-technology-backfill controller in small batches.
CREATE TABLE asset_technologies (
    tenant_id  UUID         NOT NULL,
    asset_id   UUID         NOT NULL,
    name_key   VARCHAR(128) NOT NULL,
    name       VARCHAR(128) NOT NULL,
    version    VARCHAR(64)  NOT NULL DEFAULT '',
    category   VARCHAR(20)  NOT NULL DEFAULT 'other',
    confidence SMALLINT     NOT NULL DEFAULT 0,
    source     VARCHAR(100) NOT NULL DEFAULT '',
    first_seen TIMESTAMPTZ  NOT NULL,
    last_seen  TIMESTAMPTZ  NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_asset_technologies PRIMARY KEY (tenant_id, asset_id, name_key),
    CONSTRAINT fk_asset_technologies_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_technologies_category CHECK (category IN (
        'web_server', 'framework', 'language', 'js_library', 'cdn', 'hosting',
        'waf', 'analytics', 'security_header', 'other')),
    CONSTRAINT chk_asset_technologies_confidence CHECK (confidence BETWEEN 0 AND 100),
    CONSTRAINT chk_asset_technologies_name CHECK (length(name_key) > 0 AND length(name) > 0),
    CONSTRAINT chk_asset_technologies_seen CHECK (first_seen <= last_seen)
);
COMMENT ON TABLE asset_technologies IS
    'RFC-112: technologies detected on an asset (category, version, confidence, first/last seen). Rows follow the reconciled properties.technologies.';
COMMENT ON COLUMN asset_technologies.confidence IS 'The tool''s confidence 0-100; 0 = the tool gave none.';

-- "Assets using technology X" and "assets by category" filters.
CREATE INDEX idx_asset_technologies_name ON asset_technologies (tenant_id, name_key);
CREATE INDEX idx_asset_technologies_category ON asset_technologies (tenant_id, category);

-- Tenants whose existing assets the backfill has filled, by version.
CREATE TABLE asset_technology_backfill (
    tenant_id      UUID        NOT NULL PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    version        INTEGER     NOT NULL,
    assets_scanned INTEGER     NOT NULL DEFAULT 0,
    technologies   INTEGER     NOT NULL DEFAULT 0,
    links_removed  INTEGER     NOT NULL DEFAULT 0,
    completed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE asset_technology_backfill IS
    'RFC-112: tenants whose assets the technology backfill has processed (technologies filled, non-software component links removed).';
