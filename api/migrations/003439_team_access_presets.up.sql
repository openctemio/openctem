-- Team access presets (research/298): a team carries access through managed
-- roles. A managed role belongs to exactly one team, is created from a role
-- template (or the all-assets scope role) and is changed only through the
-- team's access settings, never by hand.

ALTER TABLE roles ADD COLUMN IF NOT EXISTS managed_group_id uuid;

-- A managed role is a custom role of the team's own organization that follows
-- a template. A system role (tenant_id NULL) can never be managed.
ALTER TABLE roles ADD CONSTRAINT roles_managed_shape CHECK (
    managed_group_id IS NULL
    OR (tenant_id IS NOT NULL AND NOT is_system AND template_id IS NOT NULL)
) NOT VALID;
ALTER TABLE roles VALIDATE CONSTRAINT roles_managed_shape;

ALTER TABLE roles ADD CONSTRAINT roles_managed_group_fk
    FOREIGN KEY (managed_group_id, tenant_id) REFERENCES groups (id, tenant_id);

CREATE INDEX IF NOT EXISTS idx_roles_managed_group ON roles (managed_group_id)
    WHERE managed_group_id IS NOT NULL;

COMMENT ON COLUMN roles.managed_group_id IS
    'The team that owns this managed role (team access presets). NULL for a role managed by hand. Not editable, not assignable to a person, bound only to this team.';

-- A managed role is bound only to its own team and held only through it.
CREATE OR REPLACE FUNCTION refuse_managed_role_elsewhere() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    owner_group uuid;
BEGIN
    SELECT managed_group_id INTO owner_group FROM roles WHERE id = NEW.role_id;
    IF owner_group IS NULL THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'user_roles' THEN
        RAISE EXCEPTION 'a team-managed role cannot be assigned to a person' USING ERRCODE = 'check_violation';
    END IF;
    IF owner_group <> NEW.group_id THEN
        RAISE EXCEPTION 'a team-managed role belongs to one team' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_group_role_bindings_managed
    BEFORE INSERT ON group_role_bindings
    FOR EACH ROW EXECUTE FUNCTION refuse_managed_role_elsewhere();
CREATE TRIGGER trg_user_roles_managed
    BEFORE INSERT ON user_roles
    FOR EACH ROW EXECUTE FUNCTION refuse_managed_role_elsewhere();

-- Deleting a team deletes its managed roles (and their bindings) with it.
CREATE OR REPLACE FUNCTION delete_team_managed_roles() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM group_role_bindings
     WHERE group_id = OLD.id
       AND role_id IN (SELECT id FROM roles WHERE managed_group_id = OLD.id);
    DELETE FROM roles WHERE managed_group_id = OLD.id;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_groups_delete_managed_roles
    BEFORE DELETE ON groups
    FOR EACH ROW EXECUTE FUNCTION delete_team_managed_roles();
