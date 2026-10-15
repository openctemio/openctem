-- Invitation lifecycle (RFC-095 §5): a cancelled or declined invitation is
-- kept as revoked instead of deleted (so the daily plan limit counts what was
-- sent and the history stays), resends are rate limited, and the pending list
-- shows whether the invitee is outside the organization and whether the
-- roles need two-factor.

ALTER TABLE tenant_invitations
    ADD COLUMN IF NOT EXISTS revoked_at   timestamptz,
    ADD COLUMN IF NOT EXISTS last_sent_at timestamptz,
    ADD COLUMN IF NOT EXISTS resend_count integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS invitee_kind varchar(16),
    ADD COLUMN IF NOT EXISTS privileged   boolean NOT NULL DEFAULT false;

ALTER TABLE tenant_invitations DROP CONSTRAINT IF EXISTS chk_tenant_invitations_invitee_kind;
ALTER TABLE tenant_invitations ADD CONSTRAINT chk_tenant_invitations_invitee_kind
    CHECK (invitee_kind IS NULL OR invitee_kind IN ('internal', 'external'));
ALTER TABLE tenant_invitations DROP CONSTRAINT IF EXISTS chk_tenant_invitations_resend_count;
ALTER TABLE tenant_invitations ADD CONSTRAINT chk_tenant_invitations_resend_count CHECK (resend_count >= 0);

-- The per-inviter hourly cap counts by inviter and time.
CREATE INDEX IF NOT EXISTS idx_tenant_invitations_inviter_created
    ON tenant_invitations (invited_by, created_at);

COMMENT ON COLUMN tenant_invitations.revoked_at IS 'Cancelled by an administrator, declined by the invitee, or voided when the person was removed; the token no longer works. Purged after 30 days';
COMMENT ON COLUMN tenant_invitations.invitee_kind IS 'internal or external, as classified when the invitation was created (classified again at acceptance)';
COMMENT ON COLUMN tenant_invitations.privileged IS 'The roles are above member for an outside invitee: the inviter re-authenticated and the member needs two-factor';
