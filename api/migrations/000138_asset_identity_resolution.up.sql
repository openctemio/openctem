-- Migration 000138: Asset Identity Resolution Foundation
-- Part of RFC-001: Asset Identity Resolution & Deduplication
--
-- Creates:
-- 1. asset_merge_log — audit trail for asset merges/renames
-- 2. asset_dedup_review — admin review queue for detected duplicates

-- ============================================================
-- 1. Asset Merge Log — records every merge/rename event
-- ============================================================
CREATE TABLE IF NOT EXISTS asset_merge_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- The asset that was kept (survivor)
    kept_asset_id UUID NOT NULL,
    kept_asset_name VARCHAR(1024) NOT NULL,

    -- The asset that was merged into kept (NULL if rename only)
    merged_asset_id UUID,
    merged_asset_name VARCHAR(1024),

    -- What triggered the merge
    correlation_type VARCHAR(30) NOT NULL,
    correlation_value VARCHAR(1024),

    -- What changed
    action VARCHAR(20) NOT NULL,
    old_name VARCHAR(1024),
    new_name VARCHAR(1024),

    -- Context
    source VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_merge_log_tenant ON asset_merge_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_merge_log_kept ON asset_merge_log(kept_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_merge_log_merged ON asset_merge_log(merged_asset_id)
    WHERE merged_asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_merge_log_created ON asset_merge_log(tenant_id, created_at DESC);

-- ============================================================
-- 2. Asset Dedup Review — admin queue for duplicate groups
-- ============================================================
CREATE TABLE IF NOT EXISTS asset_dedup_review (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    normalized_name VARCHAR(1024) NOT NULL,
    asset_type VARCHAR(50) NOT NULL,

    -- The asset to keep (most findings)
    keep_asset_id UUID NOT NULL,
    keep_asset_name VARCHAR(1024) NOT NULL,
    keep_finding_count INT NOT NULL DEFAULT 0,

    -- Assets to merge into keep
    merge_asset_ids UUID[] NOT NULL,
    merge_asset_names TEXT[] NOT NULL,
    merge_finding_count INT NOT NULL DEFAULT 0,

    -- Review status
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ,
    merged_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_dedup_review_tenant ON asset_dedup_review(tenant_id);
CREATE INDEX IF NOT EXISTS idx_asset_dedup_review_status ON asset_dedup_review(tenant_id, status);

-- ============================================================
-- 3. Index for alias search (properties->'aliases')
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_assets_props_aliases
    ON assets USING GIN ((properties->'aliases'))
    WHERE properties->'aliases' IS NOT NULL;
