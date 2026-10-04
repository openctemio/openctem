-- Reverse the schema of 000800 only: allow both values again (the 000247
-- CHECK) and keep the "nothing" default. Data is NOT flipped back to
-- "everything": that would reopen the L-04 leak, and no code reads the
-- column anyway.

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_members_without_group_see;
ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_members_without_group_see
    CHECK (members_without_group_see IN ('everything', 'nothing'));

ALTER TABLE tenants ALTER COLUMN members_without_group_see SET DEFAULT 'nothing';

COMMENT ON COLUMN tenants.members_without_group_see IS
    'Data scope for members without an access group: everything (fail-open) or nothing (fail-closed). Owners/admins always see everything. Default nothing for new organizations; existing ones were set to everything by migration 000247.';
