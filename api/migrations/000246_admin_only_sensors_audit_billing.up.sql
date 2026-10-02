-- Admin-only sensors, audit log and billing (owner decision 2026-10-02).
--
-- The system member and viewer roles stop holding:
--   sensors:write          creating a sensor, rotating its key, revoking,
--                          activating or deactivating it. Each of those hands
--                          out or invalidates a sensor credential, so only
--                          owners and administrators do it. Members and
--                          viewers keep sensors:read.
--   audit:read             the organization's audit log (actor emails, IPs,
--                          every action) is for owners and administrators.
--   settings:billing:read  billing is for owners and administrators.
--
-- Owners and administrators are unaffected: they hold these permissions and
-- also bypass permission checks. Custom roles are not touched; a custom role
-- can only carry a permission its creator held, so one that carries these was
-- made deliberately by an owner or administrator.
--
-- Revocation is a row delete on the two system roles, so it reaches every
-- member and viewer of every organization at once. Cached permission sets
-- expire within their TTL (5 minutes).
DELETE FROM role_permissions
WHERE role_id IN (
        '00000000-0000-0000-0000-000000000003'::uuid, -- member
        '00000000-0000-0000-0000-000000000004'::uuid  -- viewer
      )
  AND permission_id IN ('sensors:write', 'audit:read', 'settings:billing:read');
