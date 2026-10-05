ALTER TABLE scim_group_role_mappings
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS configured_by_owner,
    DROP COLUMN IF EXISTS configured_by;
