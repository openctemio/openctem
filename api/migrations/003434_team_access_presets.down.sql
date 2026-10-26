DROP TRIGGER IF EXISTS trg_groups_delete_managed_roles ON groups;
DROP TRIGGER IF EXISTS trg_user_roles_managed ON user_roles;
DROP TRIGGER IF EXISTS trg_group_role_bindings_managed ON group_role_bindings;
DROP FUNCTION IF EXISTS delete_team_managed_roles();
DROP FUNCTION IF EXISTS refuse_managed_role_elsewhere();
-- A managed role is removed with its binding; without the column it would be
-- an ordinary custom role the team's members still hold.
DELETE FROM group_role_bindings WHERE role_id IN (SELECT id FROM roles WHERE managed_group_id IS NOT NULL);
DELETE FROM roles WHERE managed_group_id IS NOT NULL;
DROP INDEX IF EXISTS idx_roles_managed_group;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_managed_group_fk;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_managed_shape;
ALTER TABLE roles DROP COLUMN IF EXISTS managed_group_id;
