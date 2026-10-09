-- Service accounts: an organization-owned identity for an integration (a SIEM
-- export, a ticketing bridge, a reporting job). It is a user row of kind
-- 'service' that belongs to exactly one organization, has a person
-- accountable for it, and can never sign in: it acts only through API keys
-- minted for it, which carry at most the roles it holds.

ALTER TABLE users
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'person',
    ADD COLUMN service_tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    ADD COLUMN service_owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD CONSTRAINT chk_users_kind CHECK (kind IN ('person', 'service')),
    -- A service account belongs to one organization and has no credential a
    -- person could use: no password, no federated identity.
    ADD CONSTRAINT chk_users_service_account CHECK (
        (kind = 'person' AND service_tenant_id IS NULL AND service_owner_id IS NULL)
        OR (kind = 'service' AND service_tenant_id IS NOT NULL
            AND password_hash IS NULL AND federated_subject IS NULL));

COMMENT ON COLUMN users.kind IS
    'person, or service: an organization-owned identity that never signs in and acts only through API keys.';
COMMENT ON COLUMN users.service_tenant_id IS 'The one organization a service account belongs to.';
COMMENT ON COLUMN users.service_owner_id IS 'The person accountable for a service account.';

CREATE INDEX idx_users_service_tenant ON users (service_tenant_id) WHERE kind = 'service';

-- A service account is a member of its own organization only, never an owner
-- or administrator, and never holds a full-data role (directly; team
-- bindings are checked by the service).
CREATE FUNCTION refuse_service_account_membership() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    home uuid;
BEGIN
    SELECT u.service_tenant_id INTO home FROM users u WHERE u.id = NEW.user_id AND u.kind = 'service';
    IF home IS NULL THEN
        RETURN NEW;
    END IF;
    IF NEW.tenant_id <> home THEN
        RAISE EXCEPTION 'a service account belongs to one organization only'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.role IN ('owner', 'admin') THEN
        RAISE EXCEPTION 'a service account cannot be an owner or administrator'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_service_account_membership
    BEFORE INSERT OR UPDATE ON tenant_members
    FOR EACH ROW EXECUTE FUNCTION refuse_service_account_membership();

CREATE FUNCTION refuse_service_account_privileged_role() RETURNS trigger
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

CREATE TRIGGER trigger_refuse_service_account_privileged_role
    BEFORE INSERT OR UPDATE ON user_roles
    FOR EACH ROW EXECUTE FUNCTION refuse_service_account_privileged_role();
