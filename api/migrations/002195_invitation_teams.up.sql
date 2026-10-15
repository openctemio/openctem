-- Teams on an invitation (docs/rfcs/RFC-095-role-templates-and-invitations.md
-- §5): the inviter may add the invitee to teams, so a new member does not
-- join with no data. The teams are applied at acceptance, after checking that
-- the inviter can still add a member to each of them.
--
-- Live impact: a new column with an empty default on tenant_invitations
-- (metadata-only change, no table rewrite).

ALTER TABLE tenant_invitations
    ADD COLUMN IF NOT EXISTS group_ids uuid[] NOT NULL DEFAULT '{}';

ALTER TABLE tenant_invitations
    ADD CONSTRAINT chk_tenant_invitations_group_ids_count CHECK (cardinality(group_ids) <= 20);

COMMENT ON COLUMN tenant_invitations.group_ids IS
    'Teams (groups of the same organization) the invitee joins at acceptance.';
