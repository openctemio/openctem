-- Drop three asset/asset_group taxonomy columns that no application code reads
-- or writes. This is the CONTRACT step of expand-contract: the columns were
-- added speculatively and never wired to a reader/writer, so removing them is
-- backward compatible (nothing running references them).
--
--   * assets.business_unit    (000008) — the Asset domain entity has no
--     BusinessUnit field; asset_repository.go INSERT/SELECT column lists omit
--     it. No SELECT/INSERT/UPDATE anywhere in api; not exposed in swagger.
--   * asset_groups.group_type (000127) — the AssetGroup entity and
--     asset_group_repository.go never reference it; the 'dynamic' rule-based
--     value it was meant to enable was never implemented.
--   * asset_groups.properties (000127) — never SELECTed/inserted/updated by
--     asset_group_repository.go; no readers anywhere.
--
-- (NB: assets.properties [000138, GIN-indexed] and asset_groups.business_unit
-- [000024, actively read] are DIFFERENT, live columns and are left untouched.)
--
-- No index references any of the three columns, so DROP COLUMN needs no
-- accompanying DROP INDEX.
--
-- expand-contract-ok: contract step; all three columns have zero Go/SQL readers or writers (verified by rg across api + ui on 2026-08).
ALTER TABLE assets       DROP COLUMN IF EXISTS business_unit;
ALTER TABLE asset_groups DROP COLUMN IF EXISTS group_type;
ALTER TABLE asset_groups DROP COLUMN IF EXISTS properties;
