-- Reverse of 001016: the application refreshes the materialisation itself
-- again. Rows of deactivated rules that the up migration removed are
-- re-created by the next reconcile if the rule is re-activated.
DROP TRIGGER IF EXISTS scope_rule_deactivate_scope_sync ON group_asset_scope_rules;
DROP TRIGGER IF EXISTS scope_rule_delete_scope_sync ON group_asset_scope_rules;
DROP TRIGGER IF EXISTS groups_delete_scope_sync ON groups;
DROP TRIGGER IF EXISTS groups_active_scope_sync ON groups;
DROP TRIGGER IF EXISTS group_members_scope_sync ON group_members;
DROP TRIGGER IF EXISTS asset_owners_scope_sync ON asset_owners;

DROP FUNCTION IF EXISTS trg_scope_rule_scope_sync();
DROP FUNCTION IF EXISTS trg_groups_delete_scope_sync();
DROP FUNCTION IF EXISTS trg_groups_active_scope_sync();
DROP FUNCTION IF EXISTS trg_group_members_scope_sync();
DROP FUNCTION IF EXISTS trg_asset_owners_scope_sync();
