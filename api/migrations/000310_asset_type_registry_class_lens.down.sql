-- Reverts 000310. The `endpoint` row it seeded in asset_types stays: assets
-- may reference it through the asset_type FK, and 000310 upserts it again.
DROP TRIGGER IF EXISTS trg_assets_registry_class ON assets;
DROP FUNCTION IF EXISTS asset_registry_backfill(UUID, INT);
DROP FUNCTION IF EXISTS assets_sync_registry_class();
DROP FUNCTION IF EXISTS asset_type_classification(TEXT, TEXT);

ALTER TABLE assets
    DROP COLUMN IF EXISTS asset_lens,
    DROP COLUMN IF EXISTS asset_class;

DROP INDEX IF EXISTS uq_asset_types_alias;
ALTER TABLE asset_types
    DROP CONSTRAINT IF EXISTS chk_asset_types_lens,
    DROP CONSTRAINT IF EXISTS chk_asset_types_class,
    DROP COLUMN IF EXISTS alias_sub_type,
    DROP COLUMN IF EXISTS alias_of,
    DROP COLUMN IF EXISTS lens,
    DROP COLUMN IF EXISTS class;
