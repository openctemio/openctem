-- Custom roles may not carry admin-only permissions (settings decision B1,
-- 2026-10-04; owner decision 2026-10-02 "sensors and sensor keys are admin
-- only").
--
-- Migration 000246 took sensors:write away from the system member and viewer
-- roles but left custom roles alone. A custom role could still create sensors,
-- rotate and revoke their keys, change the content and result policies,
-- accept quarantined results and manage scan zones. From here on only the
-- system owner and admin roles carry:
--
--   sensors:write, sensors:delete, sensors:commands:delete,
--   sensors:zones:write, sensors:zones:delete
--
-- (pkg/domain/permission/admin_only.go; reading sensors, zones and commands
-- and queueing commands stay available to custom roles, as to members).
--
-- 1. Report: one NOTICE per affected custom role, naming the tenant, the role,
--    the permissions removed and how many users hold the role. The same rows
--    are kept in role_permissions_admin_only_stripped, so the report can be
--    read after the run and the down migration can put them back.
-- 2. Strip the permissions from every custom role (tenant_id IS NOT NULL).
-- 3. A trigger refuses a role_permissions row that would put one back on a
--    custom role. The role service refuses them first with a clear 400; the
--    trigger is the backstop for any other writer.
--
-- Live impact: a DELETE of the matching rows only (expected to be zero or a
-- handful). Holders lose the permissions at the next permission-cache expiry
-- (5 minutes) or sooner on a role change.

CREATE TABLE IF NOT EXISTS role_permissions_admin_only_stripped (
    role_id       UUID         NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tenant_id     UUID         NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    permission_id VARCHAR(100) NOT NULL,
    holders       INT          NOT NULL,
    stripped_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, permission_id)
);

COMMENT ON TABLE role_permissions_admin_only_stripped IS
    'Report of admin-only permissions removed from custom roles by migration 000913 (settings decision B1); read by the down migration';

INSERT INTO role_permissions_admin_only_stripped (role_id, tenant_id, permission_id, holders)
SELECT rp.role_id, r.tenant_id, rp.permission_id,
       (SELECT count(*) FROM user_roles ur WHERE ur.role_id = r.id)::INT
FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
WHERE r.tenant_id IS NOT NULL
  AND rp.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                           'sensors:zones:write', 'sensors:zones:delete')
ON CONFLICT (role_id, permission_id) DO NOTHING;

DO $$
DECLARE
    rec RECORD;
    n   INT := 0;
BEGIN
    FOR rec IN
        SELECT s.tenant_id, s.role_id, r.name AS role_name,
               string_agg(s.permission_id, ', ' ORDER BY s.permission_id) AS perms,
               max(s.holders) AS holders
        FROM role_permissions_admin_only_stripped s
        JOIN roles r ON r.id = s.role_id
        GROUP BY s.tenant_id, s.role_id, r.name
        ORDER BY s.tenant_id, r.name
    LOOP
        n := n + 1;
        RAISE NOTICE 'B1: tenant % role % (%): removing % (% holder(s))',
            rec.tenant_id, rec.role_id, rec.role_name, rec.perms, rec.holders;
    END LOOP;
    RAISE NOTICE 'B1: % custom role(s) carried admin-only permissions', n;
END $$;

DELETE FROM role_permissions rp
USING roles r
WHERE r.id = rp.role_id
  AND r.tenant_id IS NOT NULL
  AND rp.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                           'sensors:zones:write', 'sensors:zones:delete');

CREATE OR REPLACE FUNCTION refuse_admin_only_permission_on_custom_role()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.permission_id IN ('sensors:write', 'sensors:delete', 'sensors:commands:delete',
                             'sensors:zones:write', 'sensors:zones:delete')
       AND EXISTS (SELECT 1 FROM roles WHERE id = NEW.role_id AND tenant_id IS NOT NULL) THEN
        RAISE EXCEPTION 'permission % is reserved for the owner and admin roles and cannot be put on a custom role',
            NEW.permission_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_role_permissions_admin_only ON role_permissions;
CREATE TRIGGER trg_role_permissions_admin_only
    BEFORE INSERT OR UPDATE ON role_permissions
    FOR EACH ROW
    EXECUTE FUNCTION refuse_admin_only_permission_on_custom_role();
