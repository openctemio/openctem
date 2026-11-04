-- ctis2_asset_canonical_changes (down)
--
-- Run `asset-canonical -revert` first to give renamed assets their old names
-- back; merges are not undone (docs/operations/ctis-2-upgrade.md).
DROP TABLE IF EXISTS asset_canonical_changes;
