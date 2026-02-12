-- =============================================================================
-- Migration 000039: Asset Relationships
-- OpenCTEM OSS Edition
-- =============================================================================
-- Directed graph relationships between assets optimized for CTEM's 3 pillars:
--   1. Attack Surface Mapping: contains, runs_on, deployed_to, exposes,
--      member_of, resolves_to
--   2. Attack Path Analysis: depends_on, sends_data_to, stores_data_in,
--      authenticates_to, granted_to, load_balances
--   3. Control Gap Analysis: protected_by, monitors, manages, owned_by
--
-- 16 relationship types with metadata for confidence, discovery method,
-- impact analysis, and verification tracking.
--
-- Design decisions:
-- 1. Stores one direction (source -> target), queries both directions
-- 2. Keeps existing parent_id on assets table for backward compatibility
-- 3. UNIQUE on (tenant_id, source, target, type) allows different types
--    between same pair but prevents duplicates
-- 4. CASCADE deletes when either asset is deleted
-- =============================================================================

CREATE TABLE IF NOT EXISTS asset_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Directed edge: source -> target
    source_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    -- Relationship type (16 CTEM-optimized types)
    relationship_type VARCHAR(50) NOT NULL,

    -- Metadata
    description TEXT,
    confidence VARCHAR(10) NOT NULL DEFAULT 'medium',
    discovery_method VARCHAR(20) NOT NULL DEFAULT 'manual',

    -- Impact analysis (1-10 scale for risk scoring)
    impact_weight INTEGER NOT NULL DEFAULT 5,

    -- Tags for filtering
    tags TEXT[] DEFAULT '{}',

    -- Verification tracking
    last_verified TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- ==========================================================================
    -- Constraints
    -- ==========================================================================

    -- Prevent self-referential relationships
    CONSTRAINT chk_asset_rel_no_self_ref
        CHECK (source_asset_id != target_asset_id),

    -- Validate relationship type (16 CTEM-optimized types)
    CONSTRAINT chk_asset_rel_type CHECK (relationship_type IN (
        -- Attack Surface Mapping
        'runs_on', 'deployed_to', 'contains', 'exposes', 'member_of', 'resolves_to',
        -- Attack Path Analysis
        'depends_on', 'sends_data_to', 'stores_data_in', 'authenticates_to', 'granted_to', 'load_balances',
        -- Control & Ownership
        'protected_by', 'monitors', 'manages', 'owned_by'
    )),

    -- Validate confidence level
    CONSTRAINT chk_asset_rel_confidence CHECK (confidence IN ('high', 'medium', 'low')),

    -- Validate discovery method
    CONSTRAINT chk_asset_rel_discovery CHECK (discovery_method IN (
        'automatic', 'manual', 'imported', 'inferred'
    )),

    -- Validate impact weight (1-10)
    CONSTRAINT chk_asset_rel_impact CHECK (impact_weight >= 1 AND impact_weight <= 10),

    -- Unique relationship: same source, target, and type within a tenant
    CONSTRAINT uq_asset_relationship UNIQUE (tenant_id, source_asset_id, target_asset_id, relationship_type)
);

COMMENT ON TABLE asset_relationships IS 'Directed graph relationships between assets (CTEM-optimized)';
COMMENT ON COLUMN asset_relationships.relationship_type IS 'Type: runs_on, deployed_to, contains, exposes, member_of, resolves_to, depends_on, sends_data_to, stores_data_in, authenticates_to, granted_to, load_balances, protected_by, monitors, manages, owned_by';
COMMENT ON COLUMN asset_relationships.confidence IS 'Confidence level: high, medium, low';
COMMENT ON COLUMN asset_relationships.discovery_method IS 'How discovered: automatic, manual, imported, inferred';
COMMENT ON COLUMN asset_relationships.impact_weight IS 'Impact weight 1-10 for blast radius / risk analysis';
COMMENT ON COLUMN asset_relationships.last_verified IS 'When the relationship was last verified to still exist';

-- =============================================================================
-- Indexes
-- =============================================================================

-- Primary query: get all relationships for an asset (both directions)
CREATE INDEX IF NOT EXISTS idx_asset_rel_source
    ON asset_relationships(tenant_id, source_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_rel_target
    ON asset_relationships(tenant_id, target_asset_id);

-- Query by type within tenant
CREATE INDEX IF NOT EXISTS idx_asset_rel_type
    ON asset_relationships(tenant_id, relationship_type);

-- Graph traversal: get neighbors by type
CREATE INDEX IF NOT EXISTS idx_asset_rel_source_type
    ON asset_relationships(source_asset_id, relationship_type);
CREATE INDEX IF NOT EXISTS idx_asset_rel_target_type
    ON asset_relationships(target_asset_id, relationship_type);

-- Tags filtering (GIN for array containment)
CREATE INDEX IF NOT EXISTS idx_asset_rel_tags
    ON asset_relationships USING GIN(tags);

-- Temporal queries
CREATE INDEX IF NOT EXISTS idx_asset_rel_created
    ON asset_relationships(created_at DESC);

-- Stale verification detection
CREATE INDEX IF NOT EXISTS idx_asset_rel_verified
    ON asset_relationships(last_verified DESC)
    WHERE last_verified IS NOT NULL;

-- =============================================================================
-- Triggers
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_asset_relationships_updated_at ON asset_relationships;
CREATE TRIGGER trigger_asset_relationships_updated_at
    BEFORE UPDATE ON asset_relationships
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
