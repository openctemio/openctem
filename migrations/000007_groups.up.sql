-- =============================================================================
-- Migration 007: Groups and Access Control
-- OpenCTEM OSS Edition
-- =============================================================================

-- Groups (User groups for access control)
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) NOT NULL,
    description TEXT,
    group_type VARCHAR(50) DEFAULT 'team',
    external_id VARCHAR(255),
    external_source VARCHAR(50),
    settings JSONB DEFAULT '{}'::jsonb,
    notification_config JSONB DEFAULT '{}'::jsonb,
    metadata JSONB DEFAULT '{}'::jsonb,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    UNIQUE(tenant_id, slug),
    CONSTRAINT chk_groups_type CHECK (group_type IN ('security_team', 'team', 'department', 'project', 'external'))
);

COMMENT ON TABLE groups IS 'User groups for organizing members and asset ownership';
COMMENT ON COLUMN groups.group_type IS 'Type: security_team, team, department, project, external';

-- Group Members
CREATE TABLE IF NOT EXISTS group_members (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) DEFAULT 'member',
    joined_at TIMESTAMPTZ DEFAULT NOW(),
    added_by UUID REFERENCES users(id),

    PRIMARY KEY (group_id, user_id),
    CONSTRAINT chk_group_members_role CHECK (role IN ('owner', 'lead', 'member'))
);

COMMENT ON TABLE group_members IS 'Membership of users in groups';

-- =============================================================================
-- Indexes
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_groups_tenant ON groups(tenant_id);
CREATE INDEX IF NOT EXISTS idx_groups_type ON groups(tenant_id, group_type);
CREATE INDEX IF NOT EXISTS idx_groups_external ON groups(external_source, external_id) WHERE external_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user_group ON group_members(user_id, group_id);

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_groups_updated_at ON groups;
CREATE TRIGGER trigger_groups_updated_at
    BEFORE UPDATE ON groups
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
