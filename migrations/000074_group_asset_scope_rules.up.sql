-- =============================================================================
-- Migration 000074: Group Asset Scope Rules
-- =============================================================================
-- Adds dynamic asset-to-group scoping via tags and asset group membership.
-- When a scope rule matches, assets are auto-assigned to groups.
-- =============================================================================

-- Scope rules table
CREATE TABLE IF NOT EXISTS group_asset_scope_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',

    -- Rule type
    rule_type VARCHAR(30) NOT NULL,

    -- For tag_match rules
    match_tags TEXT[] DEFAULT '{}',
    match_logic VARCHAR(5) DEFAULT 'any',

    -- For asset_group_match rules
    match_asset_group_ids UUID[] DEFAULT '{}',

    -- Assignment config
    ownership_type VARCHAR(50) NOT NULL DEFAULT 'secondary',

    -- Rule management
    priority INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,

    -- Audit
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,

    CONSTRAINT chk_scope_rule_type CHECK (rule_type IN ('tag_match', 'asset_group_match')),
    CONSTRAINT chk_scope_match_logic CHECK (match_logic IN ('any', 'all')),
    CONSTRAINT chk_scope_ownership_type CHECK (
        ownership_type IN ('primary', 'secondary', 'stakeholder', 'informed')
    )
);

CREATE INDEX idx_scope_rules_tenant ON group_asset_scope_rules(tenant_id) WHERE is_active = TRUE;
CREATE INDEX idx_scope_rules_group ON group_asset_scope_rules(group_id);
CREATE INDEX idx_scope_rules_tags ON group_asset_scope_rules USING GIN(match_tags);
CREATE INDEX idx_scope_rules_asset_groups ON group_asset_scope_rules USING GIN(match_asset_group_ids);

-- Add assignment_source and scope_rule_id to asset_owners for tracking
ALTER TABLE asset_owners
    ADD COLUMN IF NOT EXISTS assignment_source VARCHAR(30) DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS scope_rule_id UUID REFERENCES group_asset_scope_rules(id) ON DELETE SET NULL;

-- Backfill existing rows as manual
UPDATE asset_owners SET assignment_source = 'manual' WHERE assignment_source IS NULL;

-- Index for fast lookup of auto-assigned assets
CREATE INDEX IF NOT EXISTS idx_asset_owners_scope_rule ON asset_owners(scope_rule_id) WHERE scope_rule_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_owners_source ON asset_owners(assignment_source);
