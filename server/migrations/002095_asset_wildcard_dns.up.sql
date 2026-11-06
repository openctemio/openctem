-- Names that resolve only through a wildcard DNS record (RFC-088 decision
-- A4). A completed resolution with the wildcard-DNS filter on that was given
-- the name and did not report it marks the name; a later filtered resolution
-- that reports it clears the mark. While marked, the active-scan gate treats
-- the name as passive only (unless a person confirmed it) and the scope join
-- never confirms it automatically.
--
-- Live impact: a new, empty table. Names are marked from the next completed
-- filtered resolution on; nothing existing changes.

CREATE TABLE IF NOT EXISTS asset_wildcard_dns (
    tenant_id   uuid        NOT NULL,
    asset_id    uuid        NOT NULL,
    -- The resolution that dropped the name (no foreign key: commands are
    -- purged on their own schedule; the mark stays until a resolution
    -- clears it).
    command_id  uuid,
    observed_at timestamptz NOT NULL,
    CONSTRAINT pk_asset_wildcard_dns PRIMARY KEY (tenant_id, asset_id),
    CONSTRAINT fk_asset_wildcard_dns_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);

COMMENT ON TABLE asset_wildcard_dns IS
    'RFC-088 A4: names a filtered resolution did not report (they resolve only through a wildcard record); passive only until confirmed by a person or resolved past the filter.';
