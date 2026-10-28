-- Read-only review query for accounts created by registering with an
-- invitation token before an invitation stopped proving the mailbox.
-- Run it on a read replica or inside `BEGIN READ ONLY; ... ROLLBACK;`.
-- It changes nothing.
--
-- Lists verified accounts whose sign-up source is an invitation, where:
--   * the account holds a membership, or the address has a pending
--     invitation, in an organization other than the one that invited it
--     first.
-- Review each row with the organization that holds the address; if the
-- account is not the real holder, suspend it and remove the membership.
-- signup_events keeps the domain, not the address, and is retained 90 days,
-- so the earliest invitation per address stands in for the inviter.
BEGIN READ ONLY;

WITH first_invite AS (
    SELECT DISTINCT ON (lower(email)) lower(email) AS email, tenant_id, created_at
    FROM tenant_invitations
    ORDER BY lower(email), created_at
),
invited_accounts AS (
    SELECT u.id AS user_id, lower(u.email) AS email, u.created_at, u.email_verified
    FROM users u
    JOIN signup_events se ON se.user_id = u.id
     AND se.kind = 'account_created' AND se.source = 'invitation'
    WHERE u.email_verified
)
SELECT ia.user_id,
       ia.email,
       ia.created_at,
       fi.tenant_id AS first_inviting_tenant,
       (SELECT array_agg(DISTINCT tm.tenant_id) FROM tenant_members tm
         WHERE tm.user_id = ia.user_id AND tm.tenant_id <> fi.tenant_id) AS other_memberships,
       (SELECT array_agg(DISTINCT ti.tenant_id) FROM tenant_invitations ti
         WHERE lower(ti.email) = ia.email AND ti.tenant_id <> fi.tenant_id
           AND ti.accepted_at IS NULL) AS other_pending_invitations
FROM invited_accounts ia
JOIN first_invite fi ON fi.email = ia.email
WHERE EXISTS (SELECT 1 FROM tenant_members tm
               WHERE tm.user_id = ia.user_id AND tm.tenant_id <> fi.tenant_id)
   OR EXISTS (SELECT 1 FROM tenant_invitations ti
               WHERE lower(ti.email) = ia.email AND ti.tenant_id <> fi.tenant_id
                 AND ti.accepted_at IS NULL)
ORDER BY ia.created_at DESC;

ROLLBACK;
