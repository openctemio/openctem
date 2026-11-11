-- Back to "every invitation was sent at least once": a never-sent invitation
-- is recorded as sent once at its creation time.
ALTER TABLE organization_owner_invitations
    DROP CONSTRAINT IF EXISTS chk_owner_invitation_sent_at;
UPDATE organization_owner_invitations
   SET send_count = 1, last_sent_at = created_at
 WHERE send_count = 0 OR last_sent_at IS NULL;
ALTER TABLE organization_owner_invitations
    ALTER COLUMN last_sent_at SET NOT NULL;
ALTER TABLE organization_owner_invitations
    DROP CONSTRAINT chk_owner_invitation_send_count;
ALTER TABLE organization_owner_invitations
    ADD CONSTRAINT chk_owner_invitation_send_count CHECK (send_count >= 1);
