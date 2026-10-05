-- Member lifecycle: disable, offboard, erase personal data.
-- Design: docs/rfcs/RFC-050-asset-access-model.md (research doc 21, owner
-- decisions A1-A13 and the member-lifecycle follow-up of 2026-10-04).
--
-- A person is never hard-deleted. Three actions, none of which deletes rows:
--
--   * disable  (tenant_members.status = 'suspended'): access is cut at once,
--     groups, grants and ownership stay frozen, owned schedules are paused.
--     Reversible.
--   * offboard (tenant_members.status = 'offboarded'): permanent. Groups,
--     grants, engagements, roles and keys are stripped, owned work is
--     reassigned, and the membership row stays as a tombstone so foreign keys
--     and history keep pointing at a real row. A re-invite starts from zero.
--   * erase    (users.erased_at): name and email anonymised after offboarding.
--
-- The materialised scope (user_accessible_assets) only ever holds rows for an
-- ACTIVE principal: active membership AND active user. The refresh functions
-- below enforce that, so every read that joins user_accessible_assets fails
-- closed for a disabled or offboarded member without touching each query.
--
-- Live-data impact: tenant_members, api_keys and users are small. The CHECK
-- swaps scan them once. The cleanup DELETE only touches rows of members that
-- are already suspended (whose access the request gate already refuses).

-- 1. Membership status: add 'offboarded' and who/when.
ALTER TABLE tenant_members
    ADD COLUMN IF NOT EXISTS offboarded_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS offboarded_by UUID REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE tenant_members DROP CONSTRAINT IF EXISTS chk_tenant_members_status;
ALTER TABLE tenant_members
    ADD CONSTRAINT chk_tenant_members_status
    CHECK (status IN ('active', 'suspended', 'offboarded'));

CREATE INDEX IF NOT EXISTS idx_tenant_members_offboarded
    ON tenant_members (tenant_id)
    WHERE status = 'offboarded';

COMMENT ON COLUMN tenant_members.status IS
    'Membership lifecycle: active; suspended (disabled: access cut, groups/grants frozen, reversible); offboarded (tombstone: access stripped, kept for history and foreign keys).';
COMMENT ON COLUMN tenant_members.offboarded_at IS 'When the member was offboarded. NULL unless status = offboarded.';
COMMENT ON COLUMN tenant_members.offboarded_by IS 'Who offboarded the member. NULL for a system (SCIM) offboarding.';

-- 2. API keys: a disabled member's keys are suspended (reversible), an
-- offboarded member's keys are revoked.
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS chk_api_key_status;
ALTER TABLE api_keys
    ADD CONSTRAINT chk_api_key_status
    CHECK (status IN ('active', 'expired', 'revoked', 'suspended'));

-- 3. Users: when the personal data was erased.
ALTER TABLE users ADD COLUMN IF NOT EXISTS erased_at TIMESTAMPTZ;
COMMENT ON COLUMN users.erased_at IS
    'When the name and email were anonymised (member lifecycle: erase personal data). The row and every foreign key to it stay.';

-- 4. The principal gate shared by every refresh function.
CREATE OR REPLACE FUNCTION principal_is_active(p_tenant_id UUID, p_user_id UUID)
RETURNS boolean AS $$
    SELECT EXISTS (
        SELECT 1
        FROM tenant_members tm
        JOIN users u ON u.id = tm.user_id
        WHERE tm.tenant_id = p_tenant_id
          AND tm.user_id = p_user_id
          AND tm.status = 'active'
          AND u.status = 'active'
    );
$$ LANGUAGE sql STABLE;

-- 5. Recompute one user's scope in one tenant from its sources (groups and
-- grants). An inactive principal ends with no row.
CREATE OR REPLACE FUNCTION refresh_access_for_user(p_tenant_id UUID, p_user_id UUID)
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets
    WHERE tenant_id = p_tenant_id AND user_id = p_user_id;

    IF NOT principal_is_active(p_tenant_id, p_user_id) THEN
        RETURN;
    END IF;

    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE AND g.tenant_id = p_tenant_id
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    JOIN assets a ON a.id = ao.asset_id AND a.tenant_id = g.tenant_id
    WHERE gm.user_id = p_user_id
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE aag.tenant_id = p_tenant_id AND aag.user_id = p_user_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- 6. The incremental and full refreshes admit active principals only.
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
      AND principal_is_active(g.tenant_id, gm.user_id)
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
      AND principal_is_active(g.tenant_id, p_user_id)
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
      AND principal_is_active(aag.tenant_id, aag.user_id)
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
    WHERE principal_is_active(g.tenant_id, gm.user_id)
    UNION
    SELECT DISTINCT aag.user_id, aag.tenant_id, aag.asset_id, 'secondary'
    FROM asset_access_grants aag
    WHERE principal_is_active(aag.tenant_id, aag.user_id)
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- 7. Drop the scope rows of principals that are already inactive. Their
-- sources (groups, grants) stay frozen; re-enabling recomputes the rows.
DELETE FROM user_accessible_assets uaa
WHERE NOT EXISTS (
    SELECT 1
    FROM tenant_members tm
    JOIN users u ON u.id = tm.user_id
    WHERE tm.tenant_id = uaa.tenant_id
      AND tm.user_id = uaa.user_id
      AND tm.status = 'active'
      AND u.status = 'active'
);
