-- Ownership invitations (docs/architecture/organization-ownership-invitations.md).
--
-- A platform administrator who creates an organization for a person who
-- already has an account does not make them its owner: the organization is
-- created without an owner and this row invites that account. The person
-- accepts (with a recent re-authentication) or declines in the app, and until
-- then the organization has no member at all.
--
-- The invitation is bound to the account (invitee_user_id), not to the email
-- string: no other account can accept it. invitee_email is a snapshot for the
-- console and the audit trail. There is no bearer token: the invitee is
-- identified by their own session.
--
-- New table only: nothing on existing rows.

CREATE TABLE organization_owner_invitations (
    id              UUID        PRIMARY KEY,
    tenant_id       UUID        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    invitee_user_id UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    invitee_email   TEXT        NOT NULL,
    -- The platform administrator who sent it (admin_users id, no foreign key:
    -- the invitation outlives an administrator account).
    invited_by      UUID,
    status          TEXT        NOT NULL DEFAULT 'pending',
    expires_at      TIMESTAMPTZ NOT NULL,
    send_count      INTEGER     NOT NULL DEFAULT 1,
    last_sent_at    TIMESTAMPTZ NOT NULL,
    responded_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_owner_invitation_status
        CHECK (status IN ('pending', 'accepted', 'declined', 'canceled')),
    CONSTRAINT chk_owner_invitation_send_count CHECK (send_count >= 1)
);

-- At most one pending invitation per organization.
CREATE UNIQUE INDEX uq_owner_invitations_pending
    ON organization_owner_invitations (tenant_id) WHERE status = 'pending';
CREATE INDEX idx_owner_invitations_tenant
    ON organization_owner_invitations (tenant_id, created_at DESC);
CREATE INDEX idx_owner_invitations_invitee_pending
    ON organization_owner_invitations (invitee_user_id) WHERE status = 'pending';
