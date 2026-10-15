ALTER TABLE tenant_invitations DROP CONSTRAINT IF EXISTS chk_tenant_invitations_group_ids_count;
ALTER TABLE tenant_invitations DROP COLUMN IF EXISTS group_ids;
