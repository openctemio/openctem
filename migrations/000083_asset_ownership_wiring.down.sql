-- =============================================================================
-- Migration 083 Down: Asset Ownership Wiring (Rollback)
-- =============================================================================

-- Remove new incremental refresh functions
DROP FUNCTION IF EXISTS refresh_access_for_direct_owner_add(UUID, UUID, VARCHAR);
DROP FUNCTION IF EXISTS refresh_access_for_direct_owner_remove(UUID, UUID);

-- Restore original refresh function (group-only)
CREATE OR REPLACE FUNCTION refresh_user_accessible_assets()
RETURNS void AS $$
BEGIN
    DELETE FROM user_accessible_assets;
    INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type)
    SELECT DISTINCT gm.user_id, g.tenant_id, ao.asset_id, ao.ownership_type
    FROM group_members gm
    JOIN groups g ON g.id = gm.group_id AND g.is_active = TRUE
    JOIN asset_owners ao ON ao.group_id = gm.group_id
    ON CONFLICT (user_id, tenant_id, asset_id) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- Restore original ownership_type CHECK constraint (without 'regulatory')
ALTER TABLE asset_owners DROP CONSTRAINT IF EXISTS chk_ownership_type;
ALTER TABLE asset_owners ADD CONSTRAINT chk_ownership_type
    CHECK (ownership_type IN ('primary', 'secondary', 'stakeholder', 'informed'));

-- Refresh to remove direct user access entries
SELECT refresh_user_accessible_assets();
