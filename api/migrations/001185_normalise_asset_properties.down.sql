-- Restore the asset properties migration 001185 normalised, from the copy
-- it kept. A row changed after the up migration gets its pre-001185
-- properties back (that change is lost); updated_at is not touched.

ALTER TABLE assets DISABLE TRIGGER trigger_assets_updated_at;
UPDATE assets a
SET properties = b.properties
FROM asset_properties_pre_001185 b
WHERE b.asset_id = a.id AND b.tenant_id = a.tenant_id;
ALTER TABLE assets ENABLE TRIGGER trigger_assets_updated_at;

DROP TABLE asset_properties_pre_001185;
