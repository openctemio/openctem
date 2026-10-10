-- Asset source precedence per attribute class (RFC-069 §12): a "feed" source
-- kind for passive and published feeds (a program feed, passive DNS).
ALTER TABLE asset_attribute_sources DROP CONSTRAINT IF EXISTS chk_asset_attribute_sources_kind;
ALTER TABLE asset_attribute_sources ADD CONSTRAINT chk_asset_attribute_sources_kind
    CHECK (source_kind IN ('manual', 'integration', 'import', 'scan', 'feed')) NOT VALID;
ALTER TABLE asset_attribute_sources VALIDATE CONSTRAINT chk_asset_attribute_sources_kind;
