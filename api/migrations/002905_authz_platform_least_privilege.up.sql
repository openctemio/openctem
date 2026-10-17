-- expand-contract-ok: every row is backfilled to true first and the old api always writes a bool (never NULL) for include_details, so the NOT NULL cannot reject an old pod write.
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
--    severity, link) unless it opts in to details. Channels that exist today
--    keep what they send now (full details): the ones with a NULL value or no
--    extension row yet are set to true explicitly, so only channels created
--    after this migration default to minimal. The column becomes NOT NULL so
--    a missing value can never read as either.
UPDATE integration_notification_extensions SET include_details = true WHERE include_details IS NULL;

-- Event types and severities are written as the values the repository already
-- reads for a channel without a row, so the channel behaves as before.
INSERT INTO integration_notification_extensions (integration_id, enabled_severities, enabled_event_types, include_details)
SELECT i.id, '["critical", "high"]'::jsonb, '["new_finding", "new_exposure"]'::jsonb, true
FROM integrations i
WHERE i.category = 'notification'
  AND NOT EXISTS (SELECT 1 FROM integration_notification_extensions n WHERE n.integration_id = i.id);

ALTER TABLE integration_notification_extensions ALTER COLUMN include_details SET DEFAULT false;
ALTER TABLE integration_notification_extensions ALTER COLUMN include_details SET NOT NULL;
