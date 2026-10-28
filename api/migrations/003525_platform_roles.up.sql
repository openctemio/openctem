-- Platform roles (RFC-134): the console's own role-based access control,
-- separate from the tenant one. Three new tables, used only by the console
-- (the console database role writes them; the tenant role gets no grant, see
-- deploy/postgres/least-privilege-roles.sql). No foreign key links them to the
-- tenant tables roles, role_permissions, permissions, user_roles or
-- tenant_members, and their permission keys live in their own namespace
-- (platform.*), which the tenant catalog may never use.
--
-- While the console moves from the three tiers of admin_users.role to roles,
-- each administrator holds exactly one base role standing for that column
-- (super_admin -> platform_owner, ops_admin -> platform_admin, readonly ->
-- platform_viewer); a trigger keeps it in step with the column, so every
-- path that writes the column (the console, bootstrap-admin) stays correct.
-- Other roles (operator, support, security_auditor, billing) are held in
-- addition. The built-in roles' permissions are defined in code
-- (pkg/domain/platformauthz); the rows below mirror them, and a test keeps
-- both equal.
--
-- New, empty tables plus a backfill of one row per administrator (a handful):
-- no lock on populated tables beyond the short one to add the trigger and the
-- two tenant-side CHECK constraints (validated without blocking writes).

CREATE TABLE platform_roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key         text NOT NULL UNIQUE CHECK (key ~ '^[a-z][a-z0-9_]{1,62}$'),
    name        text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
    description text NOT NULL DEFAULT '',
    builtin     boolean NOT NULL DEFAULT false,
    -- A base role stands for a tier; an administrator holds exactly one.
    base        boolean NOT NULL DEFAULT false,
    tier        text NOT NULL DEFAULT 'readonly' CHECK (tier IN ('super_admin', 'ops_admin', 'readonly')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE platform_role_permissions (
    role_id    uuid NOT NULL REFERENCES platform_roles (id) ON DELETE CASCADE,
    permission text NOT NULL CHECK (permission LIKE 'platform.%'),
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE platform_role_assignments (
    admin_id   uuid NOT NULL REFERENCES admin_users (id) ON DELETE CASCADE,
    role_id    uuid NOT NULL REFERENCES platform_roles (id) ON DELETE RESTRICT,
    -- Reserved for per-cell or per-region staff scoping; '*' only for now.
    scope      text NOT NULL DEFAULT '*' CHECK (scope = '*'),
    granted_by uuid REFERENCES admin_users (id) ON DELETE SET NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (admin_id, role_id, scope)
);
CREATE INDEX idx_platform_role_assignments_role ON platform_role_assignments (role_id);

COMMENT ON TABLE platform_roles IS 'Platform (console) roles, RFC-134. Never joined with the tenant roles.';
COMMENT ON TABLE platform_role_assignments IS 'Which platform administrator holds which platform role, RFC-134.';

INSERT INTO platform_roles (key, name, description, builtin, base, tier) VALUES
    ('platform_owner', 'Platform owner', 'Every platform permission. Keep at least two named owners and a break-glass account.', true, true, 'super_admin'),
    ('platform_admin', 'Platform admin', 'Day-to-day administration of organizations and accounts; no platform settings, administrators or identity.', true, true, 'ops_admin'),
    ('platform_viewer', 'Read-only', 'Reads the console: counts, settings and the audit log, without people''s details.', true, true, 'readonly'),
    ('operator', 'Operator', 'Runs the shared sensor fleet and the feeds; suspends an organization for abuse.', true, false, 'readonly'),
    ('support', 'Support', 'Helps people sign in and reads inside support grants organizations give.', true, false, 'readonly'),
    ('security_auditor', 'Security auditor', 'Reads the audit log, administrators and approvals for reviews; changes nothing.', true, false, 'readonly'),
    ('billing', 'Billing', 'Sets organizations'' limits and plans.', true, false, 'readonly');

INSERT INTO platform_role_permissions (role_id, permission)
SELECT r.id, v.permission
FROM (VALUES
    ('platform_owner', 'platform.admins.manage'),
    ('platform_owner', 'platform.admins.read'),
    ('platform_owner', 'platform.ai_clients.manage'),
    ('platform_owner', 'platform.announcements.write'),
    ('platform_owner', 'platform.approvals.decide'),
    ('platform_owner', 'platform.approvals.read'),
    ('platform_owner', 'platform.audit.read'),
    ('platform_owner', 'platform.console.read'),
    ('platform_owner', 'platform.content.manage'),
    ('platform_owner', 'platform.feeds.manage'),
    ('platform_owner', 'platform.identity.manage'),
    ('platform_owner', 'platform.roles.assign'),
    ('platform_owner', 'platform.roles.read'),
    ('platform_owner', 'platform.sensors.jobs.read'),
    ('platform_owner', 'platform.sensors.manage'),
    ('platform_owner', 'platform.sensors.read'),
    ('platform_owner', 'platform.settings.ai.write'),
    ('platform_owner', 'platform.settings.email.write'),
    ('platform_owner', 'platform.settings.general.write'),
    ('platform_owner', 'platform.settings.legal.write'),
    ('platform_owner', 'platform.settings.limits.write'),
    ('platform_owner', 'platform.settings.read'),
    ('platform_owner', 'platform.settings.signup.write'),
    ('platform_owner', 'platform.support.access'),
    ('platform_owner', 'platform.tenants.audit_chain.write'),
    ('platform_owner', 'platform.tenants.create'),
    ('platform_owner', 'platform.tenants.lifecycle'),
    ('platform_owner', 'platform.tenants.limits.write'),
    ('platform_owner', 'platform.tenants.members.read'),
    ('platform_owner', 'platform.tenants.owner_bootstrap'),
    ('platform_owner', 'platform.tenants.owner_recovery'),
    ('platform_owner', 'platform.tenants.purge'),
    ('platform_owner', 'platform.tenants.read'),
    ('platform_owner', 'platform.tenants.scan_policy.write'),
    ('platform_owner', 'platform.tenants.sso.write'),
    ('platform_owner', 'platform.users.read'),
    ('platform_owner', 'platform.users.support'),
    ('platform_admin', 'platform.ai_clients.manage'),
    ('platform_admin', 'platform.announcements.write'),
    ('platform_admin', 'platform.audit.read'),
    ('platform_admin', 'platform.console.read'),
    ('platform_admin', 'platform.feeds.manage'),
    ('platform_admin', 'platform.roles.read'),
    ('platform_admin', 'platform.sensors.jobs.read'),
    ('platform_admin', 'platform.sensors.read'),
    ('platform_admin', 'platform.settings.read'),
    ('platform_admin', 'platform.support.access'),
    ('platform_admin', 'platform.tenants.create'),
    ('platform_admin', 'platform.tenants.lifecycle'),
    ('platform_admin', 'platform.tenants.limits.write'),
    ('platform_admin', 'platform.tenants.members.read'),
    ('platform_admin', 'platform.tenants.owner_bootstrap'),
    ('platform_admin', 'platform.tenants.read'),
    ('platform_admin', 'platform.users.read'),
    ('platform_admin', 'platform.users.support'),
    ('platform_viewer', 'platform.audit.read'),
    ('platform_viewer', 'platform.console.read'),
    ('platform_viewer', 'platform.roles.read'),
    ('platform_viewer', 'platform.sensors.read'),
    ('platform_viewer', 'platform.settings.read'),
    ('platform_viewer', 'platform.tenants.read'),
    ('operator', 'platform.audit.read'),
    ('operator', 'platform.console.read'),
    ('operator', 'platform.feeds.manage'),
    ('operator', 'platform.roles.read'),
    ('operator', 'platform.sensors.jobs.read'),
    ('operator', 'platform.sensors.manage'),
    ('operator', 'platform.sensors.read'),
    ('operator', 'platform.settings.read'),
    ('operator', 'platform.tenants.lifecycle'),
    ('operator', 'platform.tenants.read'),
    ('support', 'platform.audit.read'),
    ('support', 'platform.console.read'),
    ('support', 'platform.roles.read'),
    ('support', 'platform.sensors.read'),
    ('support', 'platform.settings.read'),
    ('support', 'platform.support.access'),
    ('support', 'platform.tenants.members.read'),
    ('support', 'platform.tenants.read'),
    ('support', 'platform.users.read'),
    ('support', 'platform.users.support'),
    ('security_auditor', 'platform.admins.read'),
    ('security_auditor', 'platform.approvals.read'),
    ('security_auditor', 'platform.audit.read'),
    ('security_auditor', 'platform.console.read'),
    ('security_auditor', 'platform.roles.read'),
    ('security_auditor', 'platform.sensors.read'),
    ('security_auditor', 'platform.settings.read'),
    ('security_auditor', 'platform.tenants.read'),
    ('billing', 'platform.audit.read'),
    ('billing', 'platform.console.read'),
    ('billing', 'platform.roles.read'),
    ('billing', 'platform.sensors.read'),
    ('billing', 'platform.settings.read'),
    ('billing', 'platform.tenants.limits.write'),
    ('billing', 'platform.tenants.read')
) AS v(role_key, permission)
JOIN platform_roles r ON r.key = v.role_key;

-- The base role follows admin_users.role.
CREATE FUNCTION sync_platform_base_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    want text := CASE NEW.role WHEN 'super_admin' THEN 'platform_owner'
                               WHEN 'ops_admin' THEN 'platform_admin'
                               ELSE 'platform_viewer' END;
BEGIN
    DELETE FROM platform_role_assignments a
    USING platform_roles r
    WHERE a.admin_id = NEW.id AND r.id = a.role_id AND r.base AND r.key <> want;
    INSERT INTO platform_role_assignments (admin_id, role_id)
    SELECT NEW.id, r.id FROM platform_roles r WHERE r.key = want
    ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_sync_platform_base_role
    AFTER INSERT OR UPDATE OF role ON admin_users
    FOR EACH ROW EXECUTE FUNCTION sync_platform_base_role();

INSERT INTO platform_role_assignments (admin_id, role_id)
SELECT a.id, r.id
FROM admin_users a
JOIN platform_roles r ON r.key = CASE a.role WHEN 'super_admin' THEN 'platform_owner'
                                             WHEN 'ops_admin' THEN 'platform_admin'
                                             ELSE 'platform_viewer' END
ON CONFLICT DO NOTHING;

-- A break-glass account holds its base role only: extra roles are refused
-- both ways (giving one to a break-glass account, marking an account that
-- holds one as break-glass). Both triggers take one lock per account, so a
-- concurrent grant and flag change cannot both pass.
CREATE FUNCTION forbid_break_glass_extra_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('break_glass_base_role_only:' || NEW.admin_id::text));
    IF EXISTS (SELECT 1 FROM platform_roles WHERE id = NEW.role_id AND NOT base)
       AND EXISTS (SELECT 1 FROM admin_users WHERE id = NEW.admin_id AND is_break_glass) THEN
        RAISE EXCEPTION 'a break-glass account holds its base platform role only'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'break_glass_base_role_only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_forbid_break_glass_extra_role
    BEFORE INSERT OR UPDATE OF admin_id, role_id ON platform_role_assignments
    FOR EACH ROW EXECUTE FUNCTION forbid_break_glass_extra_role();

CREATE FUNCTION forbid_extra_role_for_break_glass() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.is_break_glass THEN
        PERFORM pg_advisory_xact_lock(hashtext('break_glass_base_role_only:' || NEW.id::text));
        IF EXISTS (SELECT 1 FROM platform_role_assignments a JOIN platform_roles r ON r.id = a.role_id
                   WHERE a.admin_id = NEW.id AND NOT r.base) THEN
            RAISE EXCEPTION 'an account that holds extra platform roles cannot be a break-glass account'
                USING ERRCODE = 'check_violation', CONSTRAINT = 'break_glass_base_role_only';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_forbid_extra_role_for_break_glass
    BEFORE INSERT OR UPDATE OF is_break_glass ON admin_users
    FOR EACH ROW EXECUTE FUNCTION forbid_extra_role_for_break_glass();

-- The tenant catalog never uses the platform namespace.
ALTER TABLE permissions ADD CONSTRAINT permissions_not_platform_namespace
    CHECK (id NOT LIKE 'platform.%') NOT VALID;
ALTER TABLE permissions VALIDATE CONSTRAINT permissions_not_platform_namespace;
ALTER TABLE role_permissions ADD CONSTRAINT role_permissions_not_platform_namespace
    CHECK (permission_id NOT LIKE 'platform.%') NOT VALID;
ALTER TABLE role_permissions VALIDATE CONSTRAINT role_permissions_not_platform_namespace;
