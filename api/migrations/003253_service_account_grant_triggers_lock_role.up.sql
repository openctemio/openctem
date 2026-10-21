-- The grant-side triggers read roles.has_full_data_access to refuse a
-- full-data role for a service account. Without a row lock, "turn full data on
-- for a role" (003249) running at the same time as "grant that role to a
-- service account" could each miss the other's uncommitted write. The grant
-- locks the role row FOR SHARE (reading the flag in a statement of its own: a
-- lock under a WHERE on the flag would skip a row whose committed value is
-- still false), so it waits for a role update in flight and then reads the
-- committed value; a role update in turn waits for the share lock holders.
CREATE OR REPLACE FUNCTION refuse_service_account_privileged_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    full_data boolean;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.kind = 'service') THEN
        RETURN NEW;
    END IF;
    SELECT r.has_full_data_access INTO full_data FROM roles r WHERE r.id = NEW.role_id FOR SHARE OF r;
    IF NEW.role_id IN ('00000000-0000-0000-0000-000000000001'::uuid, '00000000-0000-0000-0000-000000000002'::uuid)
       OR COALESCE(full_data, false) THEN
        RAISE EXCEPTION 'a service account cannot hold the owner or administrator role or full data access'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION refuse_full_data_binding_with_service_account() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    full_data boolean;
BEGIN
    SELECT r.has_full_data_access INTO full_data FROM roles r WHERE r.id = NEW.role_id FOR SHARE OF r;
    IF COALESCE(full_data, false)
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
    IF NOT EXISTS (SELECT 1 FROM users u WHERE u.id = NEW.user_id AND u.kind = 'service') THEN
        RETURN NEW;
    END IF;
    -- Lock every role bound to the team (in id order, so two writers never
    -- wait on each other's locks in opposite orders) before reading its flag.
    PERFORM 1 FROM roles r WHERE r.id IN (SELECT b.role_id FROM group_role_bindings b WHERE b.group_id = NEW.group_id) ORDER BY r.id FOR SHARE OF r;
    IF EXISTS (SELECT 1 FROM group_role_bindings b JOIN roles r ON r.id = b.role_id
               WHERE b.group_id = NEW.group_id AND r.has_full_data_access) THEN
        RAISE EXCEPTION 'a service account cannot join a team that has a full data role'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
