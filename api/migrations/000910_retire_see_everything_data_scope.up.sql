-- Retire the "members without an access group see everything" data-scope mode
-- (research doc 15 L-04, owner decision D2; the owner signed off on
-- 2026-10-04 to finish the retirement, which lifts the earlier rule of never
-- changing an organization's value in a migration).
--
-- Since then no code reads tenants.members_without_group_see for visibility:
-- a member with no scope row sees nothing in every organization. This is the
-- expand step: store "nothing" everywhere and make "everything" impossible to
-- store again. The contract step (dropping the column) follows after a
-- release, once no deployed binary reads it.
--
-- tenants is small; the UPDATE and the CHECK scan are short.

UPDATE tenants
SET members_without_group_see = 'nothing'
WHERE members_without_group_see IS DISTINCT FROM 'nothing';

ALTER TABLE tenants ALTER COLUMN members_without_group_see SET DEFAULT 'nothing';

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_members_without_group_see;
ALTER TABLE tenants
    ADD CONSTRAINT chk_tenants_members_without_group_see
    CHECK (members_without_group_see = 'nothing');

COMMENT ON COLUMN tenants.members_without_group_see IS
    'Retired (owner decision D2, migration 000800): always nothing, no longer read. Members without a scope row see nothing in every organization. To be dropped after a release.';
