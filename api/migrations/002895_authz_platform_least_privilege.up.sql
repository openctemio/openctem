-- Least privilege for sensor facts and the credential store.
--
-- 1. The Researcher role template (v2) no longer carries sensors:read: a
--    researcher scoped to a bug-bounty program has no business reading the
--    organization's sensor fleet (hosts, addresses, versions). Custom roles
--    created from the template lose the grant too and move to version 2.
-- 2. The built-in Member role loses scans:secret_store:write: the credential
--    store is consumed only by template sources, which are owner/admin only,
--    so writing or rotating a credential is owner/admin only as well.

DELETE FROM role_permissions rp
USING roles r
WHERE rp.role_id = r.id
  AND r.template_id = 'researcher' AND NOT r.is_system
  AND rp.permission_id = 'sensors:read';

UPDATE roles
SET template_permissions = array_remove(template_permissions, 'sensors:read'),
    template_version = 2
WHERE template_id = 'researcher' AND NOT is_system AND template_version = 1;

DELETE FROM role_permissions
WHERE role_id = '00000000-0000-0000-0000-000000000003'
  AND permission_id = 'scans:secret_store:write';

-- 3. A new notification channel sends the minimal message (event type,
--    severity, link) unless it opts in to details. Existing channels keep
--    their stored choice.
ALTER TABLE integration_notification_extensions ALTER COLUMN include_details SET DEFAULT false;
