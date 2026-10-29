-- A break-glass account holds its base platform role only (RFC-134). Kept
-- out of platform_roles (003525) so installs that already applied that
-- migration still get these triggers.

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

