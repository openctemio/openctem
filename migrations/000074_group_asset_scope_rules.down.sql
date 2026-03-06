-- Reverse migration 000074
DROP INDEX IF EXISTS idx_asset_owners_source;
DROP INDEX IF EXISTS idx_asset_owners_scope_rule;
ALTER TABLE asset_owners DROP COLUMN IF EXISTS scope_rule_id;
ALTER TABLE asset_owners DROP COLUMN IF EXISTS assignment_source;
DROP TABLE IF EXISTS group_asset_scope_rules;
