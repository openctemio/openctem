-- Program assets kept apart from the organization's own (RFC-065 §16.5).
--
-- asset_program_links is the structural provenance: which program lists or
-- covers an asset, and from which source. assets.system_tags holds the tags
-- the platform derives from it (bug-bounty, source:…, platform:…,
-- program:…:…, program-unattested); no API writes them, so people cannot
-- change them. assets.program_only marks an asset that came with a program
-- and that none of the organization's own scope covers: the organization's
-- dashboards and metrics leave those out by default.
--
-- Live impact: two columns with constant defaults (no rewrite); a partial
-- index that is empty until programs link assets; a new table.

ALTER TABLE assets
    ADD COLUMN IF NOT EXISTS system_tags  text[]  NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS program_only boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_assets_program_only ON assets (tenant_id) WHERE program_only;
CREATE INDEX IF NOT EXISTS idx_assets_system_tags ON assets USING gin (system_tags) WHERE system_tags <> '{}';

CREATE TABLE IF NOT EXISTS asset_program_links (
    tenant_id  uuid        NOT NULL,
    asset_id   uuid        NOT NULL,
    program_id uuid        NOT NULL,
    source     text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, asset_id, program_id),
    CONSTRAINT fk_asset_program_links_asset FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_program_links_program FOREIGN KEY (tenant_id, program_id)
        REFERENCES bounty_programs (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_asset_program_links_source CHECK (source IN ('programfeed', 'program_manual', 'program_import'))
);
CREATE INDEX IF NOT EXISTS idx_asset_program_links_program ON asset_program_links (tenant_id, program_id);

COMMENT ON TABLE asset_program_links IS 'Programs that list or cover an asset, with the program source (RFC-065 §16.5)';
COMMENT ON COLUMN assets.system_tags IS 'Tags the platform derives from asset_program_links; never written by people';
COMMENT ON COLUMN assets.program_only IS 'Came with a program and no own scope covers it: left out of organization metrics by default';
