-- Per-organization data-scope policy: "members without an access group see:
-- everything | nothing" (owner decision 2026-10-02).
--
-- Owners and admins always see everything and members in an access group see
-- that group's assets; this column decides only members with no group.
--   everything = fail-open (what every organization had until now)
--   nothing    = fail-closed (Tenable's "No Access")
--
-- Existing organizations keep "everything" so nobody loses access: the column
-- is added with DEFAULT 'everything', which fills every existing row. The one
-- exception is an organization that had already switched on the earlier
-- settings flag (settings.security.restricted_data_scope = true): it keeps
-- "nothing". The default is then changed to 'nothing', so every organization
-- created from now on starts fail-closed. The settings key is no longer read.

ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS members_without_group_see VARCHAR(16) NOT NULL DEFAULT 'everything';

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_members_without_group_see;
ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_members_without_group_see
    CHECK (members_without_group_see IN ('everything', 'nothing'));

UPDATE tenants
SET members_without_group_see = 'nothing'
WHERE settings -> 'security' ->> 'restricted_data_scope' = 'true'
  AND members_without_group_see <> 'nothing';

ALTER TABLE tenants ALTER COLUMN members_without_group_see SET DEFAULT 'nothing';

COMMENT ON COLUMN tenants.members_without_group_see IS
    'Data scope for members without an access group: everything (fail-open) or nothing (fail-closed). Owners/admins always see everything. Default nothing for new organizations; existing ones were set to everything by migration 000247.';
