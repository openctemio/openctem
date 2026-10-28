DROP TABLE IF EXISTS asset_group_member_history;
DROP TABLE IF EXISTS asset_group_exclusions;
DROP INDEX IF EXISTS idx_asset_group_members_rule;
DROP INDEX IF EXISTS idx_asset_groups_rule;
ALTER TABLE asset_groups
    DROP CONSTRAINT IF EXISTS chk_asset_groups_rule_status,
    DROP CONSTRAINT IF EXISTS chk_asset_groups_rule_object,
    DROP COLUMN IF EXISTS rule_evaluated_at,
    DROP COLUMN IF EXISTS rule_status,
    DROP COLUMN IF EXISTS rule_editor_id,
    DROP COLUMN IF EXISTS rule;
ALTER TABLE asset_group_members
    DROP CONSTRAINT IF EXISTS chk_asset_group_members_source,
    DROP COLUMN IF EXISTS source;
