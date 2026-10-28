-- Restores the rule that an administrator's account belongs to no
-- organization. Refuses to run while such a membership exists, so a rollback
-- never leaves rows that contradict the restored trigger.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM tenant_members m JOIN admin_users a ON a.user_id = m.user_id) THEN
        RAISE EXCEPTION 'platform administrators hold organization memberships; remove them before rolling back 003524';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_forbid_break_glass_with_membership ON admin_users;
DROP FUNCTION IF EXISTS forbid_break_glass_with_membership();
DROP TRIGGER IF EXISTS trg_forbid_break_glass_membership ON tenant_members;
DROP FUNCTION IF EXISTS forbid_break_glass_membership();

CREATE FUNCTION forbid_platform_admin_membership() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM admin_users WHERE user_id = NEW.user_id) THEN
        RAISE EXCEPTION 'platform administrators cannot be members of an organization'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_forbid_platform_admin_membership
    BEFORE INSERT OR UPDATE OF user_id ON tenant_members
    FOR EACH ROW EXECUTE FUNCTION forbid_platform_admin_membership();
