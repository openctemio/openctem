-- Revoked invitations were deleted before this migration: drop them so they
-- do not become pending again.
DELETE FROM tenant_invitations WHERE revoked_at IS NOT NULL;

DROP INDEX IF EXISTS idx_tenant_invitations_inviter_created;
ALTER TABLE tenant_invitations DROP CONSTRAINT IF EXISTS chk_tenant_invitations_resend_count;
ALTER TABLE tenant_invitations DROP CONSTRAINT IF EXISTS chk_tenant_invitations_invitee_kind;
-- expand-contract-ok: down migration of columns added by the same migration
ALTER TABLE tenant_invitations
    DROP COLUMN IF EXISTS privileged,
    DROP COLUMN IF EXISTS invitee_kind,
    DROP COLUMN IF EXISTS resend_count,
    DROP COLUMN IF EXISTS last_sent_at,
    DROP COLUMN IF EXISTS revoked_at;
