-- A service account never holds full data access (001586 refuses it on
-- user_roles). A team binding gives every member the team's roles, so the same
-- ceiling must hold through teams: the service checks it, and these triggers
-- back it up for any path that writes the tables directly.
--   * binding a full-data role to a team that has a service account member;
--   * adding a service account to a team that has a full-data role bound.
CREATE FUNCTION refuse_full_data_binding_with_service_account() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM roles r WHERE r.id = NEW.role_id AND r.has_full_data_access)
       AND EXISTS (SELECT 1 FROM group_members gm JOIN users u ON u.id = gm.user_id
                   WHERE gm.group_id = NEW.group_id AND u.kind = 'service') THEN
        RAISE EXCEPTION 'a full data role cannot be bound to a team that has a service account'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_full_data_binding_with_service_account
    BEFORE INSERT OR UPDATE ON group_role_bindings
    FOR EACH ROW EXECUTE FUNCTION refuse_full_data_binding_with_service_account();

CREATE FUNCTION refuse_service_account_in_full_data_team() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.kind = 'service')
       AND EXISTS (SELECT 1 FROM group_role_bindings b JOIN roles r ON r.id = b.role_id
                   WHERE b.group_id = NEW.group_id AND r.has_full_data_access) THEN
        RAISE EXCEPTION 'a service account cannot join a team that has a full data role'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_service_account_in_full_data_team
    BEFORE INSERT OR UPDATE ON group_members
    FOR EACH ROW EXECUTE FUNCTION refuse_service_account_in_full_data_team();
