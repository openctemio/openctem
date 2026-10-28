-- One identity for a platform administrator and an application user
-- (RFC-133): the platform role is an attribute of the one users account,
-- effective only on the console plane. The account may now be an ordinary
-- member of organizations, so the trigger that refused every administrator's
-- membership goes.
--
-- A break-glass administrator stays console-only: its credentials are sealed
-- for emergencies, and using them in an organization would mean unsealing
-- them. The new triggers refuse a membership for a break-glass account, and
-- marking (or linking) an account that holds a membership as break-glass.
-- The raise names the rule (constraint break_glass_console_only) so the
-- application can tell it from other check violations.
--
-- Dropping and creating triggers takes short locks on tenant_members and
-- admin_users and touches no row. No existing row violates the new rule: until
-- now no administrator could hold a membership at all.

DROP TRIGGER IF EXISTS trg_forbid_platform_admin_membership ON tenant_members;
DROP FUNCTION IF EXISTS forbid_platform_admin_membership();

CREATE FUNCTION forbid_break_glass_membership() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM admin_users WHERE user_id = NEW.user_id AND is_break_glass) THEN
        RAISE EXCEPTION 'a break-glass administrator account cannot be a member of an organization'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'break_glass_console_only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_forbid_break_glass_membership
    BEFORE INSERT OR UPDATE OF user_id ON tenant_members
    FOR EACH ROW EXECUTE FUNCTION forbid_break_glass_membership();

CREATE FUNCTION forbid_break_glass_with_membership() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.is_break_glass AND NEW.user_id IS NOT NULL
       AND EXISTS (SELECT 1 FROM tenant_members WHERE user_id = NEW.user_id) THEN
        RAISE EXCEPTION 'an account that belongs to an organization cannot be a break-glass administrator'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'break_glass_console_only';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_forbid_break_glass_with_membership
    BEFORE INSERT OR UPDATE OF is_break_glass, user_id ON admin_users
    FOR EACH ROW EXECUTE FUNCTION forbid_break_glass_with_membership();
