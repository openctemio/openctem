-- Asset-group members must be assets of the group's own tenant.
--
-- asset_group_members has no tenant_id. Until the add path checked the asset
-- ids, a member row could point at another tenant's asset. The API now only
-- inserts same-tenant members and every read joins members to the group's
-- tenant, so such rows are inert; this removes any that were written.
DELETE FROM asset_group_members agm
USING asset_groups ag, assets a
WHERE ag.id = agm.asset_group_id
  AND a.id = agm.asset_id
  AND a.tenant_id <> ag.tenant_id;
