-- Custom scanner templates and template sources are trusted code (owner
-- decision 2026-10-02).
--
-- A custom nuclei template is a program the sensor runs: it chooses which
-- hosts to contact and what to send, so whoever writes one decides what every
-- sensor that runs it does. A template source pulls such templates from a
-- URL into the tenant, with a stored credential. Both are owner/admin only.
--
-- The system member role stops holding:
--   scans:templates:write  create, update and deprecate scanner templates
--   scans:sources:write    create, update, enable, disable and sync template
--                          sources (scans:sources:* is used by nothing else)
-- Members keep scans:templates:read and scans:sources:read, so they can still
-- pick an approved template for a scan. The viewer role never held either.
--
-- Owners and administrators are unaffected: they hold these permissions and
-- bypass permission checks. Custom roles are not touched; a custom role can
-- only carry a permission its creator held, so one that carries these was
-- made deliberately by an owner or administrator.
--
-- Revocation is a row delete on the system role, so it reaches every member
-- of every organization at once. Cached permission sets expire within their
-- TTL (5 minutes).
DELETE FROM role_permissions
WHERE role_id = '00000000-0000-0000-0000-000000000003'::uuid -- member
  AND permission_id IN ('scans:templates:write', 'scans:sources:write');
