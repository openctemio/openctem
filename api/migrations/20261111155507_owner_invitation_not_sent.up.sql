-- An ownership invitation issued on an installation that cannot send email
-- was recorded as sent once (send_count 1, last_sent_at set) although nothing
-- was sent. From now on such an invitation is stored as never sent:
-- send_count 0 and last_sent_at NULL
-- (docs/architecture/organization-ownership-invitations.md).
--
-- Constraint and nullability change only; existing rows are untouched (whether
-- their first send really went out is not known). The table is small: one row
-- per organization created for an existing account.

ALTER TABLE organization_owner_invitations
    DROP CONSTRAINT chk_owner_invitation_send_count;
ALTER TABLE organization_owner_invitations
    ADD CONSTRAINT chk_owner_invitation_send_count CHECK (send_count >= 0);
ALTER TABLE organization_owner_invitations
    ALTER COLUMN last_sent_at DROP NOT NULL;
