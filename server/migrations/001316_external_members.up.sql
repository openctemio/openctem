-- External members: people who belong to an organization that does not own
-- their email domain. Design: docs/rfcs/RFC-058-external-members.md.
--
-- kind          internal (default; every existing membership) or external.
-- home_tenant_id the organization that holds the member's verified SSO domain
--               when the member joined (NULL: no organization manages the
--               address: a personal or an unclaimed work domain).
-- home_domain   the member's email domain when classified.
-- expires_at    when the membership is suspended automatically; mandatory
--               for unmanaged externals (enforced by the service).
-- suspended_reason why a suspension happened (expired, ...), for the UI.
ALTER TABLE tenant_members
    ADD COLUMN kind text NOT NULL DEFAULT 'internal',
    ADD COLUMN home_tenant_id uuid NULL REFERENCES tenants(id) ON DELETE SET NULL,
    ADD COLUMN home_domain text NULL,
    ADD COLUMN expires_at timestamptz NULL,
    ADD COLUMN expiry_reason text NULL,
    ADD COLUMN suspended_reason text NULL;

ALTER TABLE tenant_members
    ADD CONSTRAINT chk_tenant_members_kind CHECK (kind IN ('internal', 'external')),
    ADD CONSTRAINT chk_tenant_members_external_not_owner CHECK (kind = 'internal' OR role <> 'owner'),
    ADD CONSTRAINT chk_tenant_members_expiry_reason_len CHECK (expiry_reason IS NULL OR length(expiry_reason) <= 500);

CREATE INDEX idx_tenant_members_home ON tenant_members (home_tenant_id, user_id) WHERE kind = 'external';
CREATE INDEX idx_tenant_members_expiry ON tenant_members (expires_at) WHERE expires_at IS NOT NULL AND status = 'active';

-- The membership role column is not the whole role set (user_roles is): an
-- external member must not hold the owner role through either.
CREATE FUNCTION refuse_external_owner_role() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.role_id = '00000000-0000-0000-0000-000000000001'::uuid
       AND EXISTS (SELECT 1 FROM tenant_members m
                   WHERE m.user_id = NEW.user_id AND m.tenant_id = NEW.tenant_id AND m.kind = 'external') THEN
        RAISE EXCEPTION 'an external member cannot hold the owner role'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_external_owner_role
    BEFORE INSERT OR UPDATE ON user_roles
    FOR EACH ROW EXECUTE FUNCTION refuse_external_owner_role();

CREATE FUNCTION refuse_external_owner_member() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.kind = 'external'
       AND EXISTS (SELECT 1 FROM user_roles ur
                   WHERE ur.user_id = NEW.user_id AND ur.tenant_id = NEW.tenant_id
                     AND ur.role_id = '00000000-0000-0000-0000-000000000001'::uuid) THEN
        RAISE EXCEPTION 'an owner cannot be an external member'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_refuse_external_owner_member
    BEFORE UPDATE OF kind ON tenant_members
    FOR EACH ROW EXECUTE FUNCTION refuse_external_owner_member();

-- The invitation carries the access the inviter set for an external invitee.
ALTER TABLE tenant_invitations
    ADD COLUMN access_expires_at timestamptz NULL,
    ADD COLUMN access_expiry_reason text NULL,
    ADD CONSTRAINT chk_tenant_invitations_expiry_reason_len CHECK (access_expiry_reason IS NULL OR length(access_expiry_reason) <= 500);

COMMENT ON COLUMN tenant_members.kind IS 'internal, or external: the organization does not own the member''s email domain (RFC-058).';
COMMENT ON COLUMN tenant_members.home_tenant_id IS 'Organization holding the external member''s verified SSO domain at classification; NULL when no organization manages the address.';
COMMENT ON COLUMN tenant_members.expires_at IS 'The membership is suspended automatically at this time (suspended_reason = expired).';
