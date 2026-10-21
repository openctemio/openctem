-- A service account never holds full data access, directly (001586) or through
-- a team (003240). Both triggers fire when a role is GRANTED; turning
-- has_full_data_access on for a role a service account already holds slipped
-- past them. This trigger closes that path for any writer of roles.
CREATE FUNCTION refuse_full_data_role_with_service_account_holder() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.has_full_data_access AND NOT OLD.has_full_data_access
       AND EXISTS (SELECT 1 FROM v_user_role_grants g JOIN users u ON u.id = g.user_id
                   WHERE g.role_id = NEW.id AND u.kind = 'service') THEN
        RAISE EXCEPTION 'a role held by a service account cannot get full data access'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_full_data_role_with_service_account_holder
    BEFORE UPDATE OF has_full_data_access ON roles
    FOR EACH ROW EXECUTE FUNCTION refuse_full_data_role_with_service_account_holder();
