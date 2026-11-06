DELETE FROM asset_attribute_sources WHERE source_kind = 'feed';
ALTER TABLE asset_attribute_sources DROP CONSTRAINT IF EXISTS chk_asset_attribute_sources_kind;
ALTER TABLE asset_attribute_sources ADD CONSTRAINT chk_asset_attribute_sources_kind
    CHECK (source_kind IN ('manual', 'integration', 'import', 'scan'));
