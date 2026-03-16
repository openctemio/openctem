-- Sync missing user_roles from tenant_members
--
-- The sync_tenant_member_to_user_roles trigger handles new INSERT/UPDATE,
-- but tenant_members created before the trigger existed may be missing
-- corresponding user_roles entries. This causes "Access Denied" because
-- the permission system reads from user_roles, not tenant_members.
--
-- This migration backfills any missing entries.

INSERT INTO user_roles (user_id, role_id, tenant_id, assigned_at)
SELECT tm.user_id, r.id, tm.tenant_id, COALESCE(tm.joined_at, NOW())
FROM tenant_members tm
JOIN roles r ON r.slug = tm.role AND r.is_system = TRUE AND r.tenant_id IS NULL
LEFT JOIN user_roles ur
    ON ur.user_id = tm.user_id
    AND ur.tenant_id = tm.tenant_id
    AND ur.role_id = r.id
WHERE ur.user_id IS NULL
ON CONFLICT (user_id, role_id, tenant_id) DO NOTHING;
