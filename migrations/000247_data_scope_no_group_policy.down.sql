-- Reverse of 000247. Organizations set to "nothing" are written back to the
-- settings flag the previous code read, so they stay fail-closed.
UPDATE tenants
SET settings = jsonb_set(
        CASE WHEN jsonb_typeof(settings -> 'security') = 'object'
             THEN settings
             ELSE jsonb_set(COALESCE(settings, '{}'::jsonb), '{security}', '{}'::jsonb, true)
        END,
        '{security,restricted_data_scope}', 'true'::jsonb, true)
WHERE members_without_group_see = 'nothing';

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS chk_tenants_members_without_group_see;
ALTER TABLE tenants DROP COLUMN IF EXISTS members_without_group_see;
