-- Reverse of 000970. An offboarded tombstone becomes a suspended membership
-- (still no access), and a suspended key becomes revoked: neither state
-- exists before this migration, and both mappings keep access closed.

-- Restore the refresh functions of 000455 / 000372 (no principal gate).
CREATE OR REPLACE FUNCTION refresh_access_for_asset_assign(
    p_group_id UUID,
    p_asset_id UUID,
    p_ownership_type VARCHAR
)
RETURNS void AS $$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT gm.user_id, g.tenant_id, a.id, p_ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN assets a ON a.id = p_asset_id AND a.tenant_id = g.tenant_id
    WHERE gm.group_id = p_group_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION refresh_access_for_member_add(
    p_group_id UUID,
    p_user_id UUID
)
RETURNS void AS $$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT p_user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM asset_owners ao
    JOIN groups g ON g.id = ao.group_id AND g.is_active = TRUE
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    WHERE ao.group_id = p_group_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION refresh_access_for_grant_add(p_asset_id UUID, p_user_id UUID)
RETURNS void AS $$
BEGIN
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE aag.asset_id = p_asset_id AND aag.user_id = p_user_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

DROP FUNCTION IF EXISTS refresh_access_for_user(UUID, UUID);
DROP FUNCTION IF EXISTS principal_is_active(UUID, UUID);

ALTER TABLE users DROP COLUMN IF EXISTS erased_at;

UPDATE api_keys SET status = 'revoked', revoked_at = COALESCE(revoked_at, NOW())
WHERE status = 'suspended';
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS chk_api_key_status;
ALTER TABLE api_keys
    ADD CONSTRAINT chk_api_key_status
    CHECK (status IN ('active', 'expired', 'revoked'));

UPDATE tenant_members
SET status = 'suspended',
    suspended_at = COALESCE(suspended_at, offboarded_at, NOW()),
    suspended_by = COALESCE(suspended_by, offboarded_by)
WHERE status = 'offboarded';

DROP INDEX IF EXISTS idx_tenant_members_offboarded;
ALTER TABLE tenant_members DROP CONSTRAINT IF EXISTS chk_tenant_members_status;
ALTER TABLE tenant_members
    ADD CONSTRAINT chk_tenant_members_status
    CHECK (status IN ('active', 'suspended'));
ALTER TABLE tenant_members
    DROP COLUMN IF EXISTS offboarded_by,
    DROP COLUMN IF EXISTS offboarded_at;

COMMENT ON COLUMN tenant_members.status IS 'Membership lifecycle: active (full access) or suspended (access revoked, history preserved)';
