DROP VIEW IF EXISTS v_user_role_grants;
DROP TABLE IF EXISTS group_role_bindings;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_id_tenant_key;
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_id_tenant_key;
