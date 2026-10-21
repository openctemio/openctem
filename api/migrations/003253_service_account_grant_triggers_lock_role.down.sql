-- Restore the grant-side trigger functions without the role row lock.
CREATE OR REPLACE FUNCTION refuse_service_account_privileged_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.kind = 'service')
       AND (NEW.role_id IN ('00000000-0000-0000-0000-000000000001'::uuid, '00000000-0000-0000-0000-000000000002'::uuid)
            OR EXISTS (SELECT 1 FROM roles r WHERE r.id = NEW.role_id AND r.has_full_data_access)) THEN
        RAISE EXCEPTION 'a service account cannot hold the owner or administrator role or full data access'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION refuse_full_data_binding_with_service_account() RETURNS trigger
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

CREATE OR REPLACE FUNCTION refuse_service_account_in_full_data_team() RETURNS trigger
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
