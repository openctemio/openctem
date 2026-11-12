DROP TRIGGER IF EXISTS trg_tenant_members_snapshots_inactive ON tenant_members;
DROP TRIGGER IF EXISTS trg_tenant_members_snapshots_delete ON tenant_members;
DROP FUNCTION IF EXISTS dash_snapshots_drop_for_member();
