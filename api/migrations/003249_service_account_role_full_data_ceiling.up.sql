-- A service account never holds full data access, directly (001586) or through
-- a team (003240). Both triggers fire when a role is GRANTED; turning
-- has_full_data_access on for a role a service account already holds slipped
-- past them. This trigger closes that path for any writer of roles. It reads
-- the raw grant tables, not v_user_role_grants: the view hides inactive teams
-- and expired team memberships, which would let a role turn full-data and the
-- service account gain it when the team is re-activated.
CREATE FUNCTION refuse_full_data_role_with_service_account_holder() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.has_full_data_access AND NOT OLD.has_full_data_access
       AND (EXISTS (SELECT 1 FROM user_roles ur JOIN users u ON u.id = ur.user_id
                    WHERE ur.role_id = NEW.id AND u.kind = 'service')
            OR EXISTS (SELECT 1 FROM group_role_bindings b
                       JOIN group_members gm ON gm.group_id = b.group_id
                       JOIN users u ON u.id = gm.user_id
                       WHERE b.role_id = NEW.id AND u.kind = 'service')) THEN
        RAISE EXCEPTION 'a role held by a service account cannot get full data access'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_full_data_role_with_service_account_holder
    BEFORE UPDATE OF has_full_data_access ON roles
    FOR EACH ROW EXECUTE FUNCTION refuse_full_data_role_with_service_account_holder();
