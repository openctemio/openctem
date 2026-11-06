-- The viewer role is where every new member starts (invitations, SSO JIT,
-- SCIM, external members), so it carries only what reading the exposure
-- programme needs. Two grants went beyond that:
--   scans:secret_store:read      lists the stored scan credentials (names,
--                                 kinds, descriptions, expiry): reconnaissance
--                                 for anyone who just joined, and nothing a
--                                 reader needs;
--   team:assignment_rules:read   the member role never had it, so viewer was
--                                 not a subset of member.
-- Custom roles keep whatever their administrators gave them.
DELETE FROM role_permissions
WHERE role_id = '00000000-0000-0000-0000-000000000004'
  AND permission_id IN ('scans:secret_store:read', 'team:assignment_rules:read');
