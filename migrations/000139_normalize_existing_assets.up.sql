-- Migration 000139: Normalize Existing Asset Names
-- Part of RFC-001 Phase 1b: Data Migration
--
-- This migration normalizes existing asset names to canonical form:
-- - Domains/subdomains: lowercase, strip trailing dot
-- - Hosts: lowercase hostnames (skip IPs), strip trailing dot
-- - Repositories: lowercase, strip protocol/ssh prefix, strip .git
-- - IPs: leave as-is (Go net.ParseIP handles at ingest time)
--
-- Strategy:
-- 1. Rename assets to normalized form (chunked, safe)
-- 2. Store old name in properties.aliases for search
-- 3. Detect duplicate groups → insert into asset_dedup_review
-- 4. Do NOT auto-merge — admin must approve each group

-- ============================================================
-- Step 1: Normalize domain/subdomain names
-- ============================================================
UPDATE assets
SET
    properties = jsonb_set(
        COALESCE(properties, '{}'),
        '{aliases}',
        COALESCE(properties->'aliases', '[]'::jsonb) || to_jsonb(name)
    ),
    name = LOWER(RTRIM(LTRIM(TRIM(name), '.'), '.')),
    updated_at = NOW()
WHERE asset_type IN ('domain', 'subdomain')
  AND (name != LOWER(RTRIM(LTRIM(TRIM(name), '.'), '.'))
       OR name LIKE '%.');

-- ============================================================
-- Step 2: Normalize host names (skip IPs)
-- ============================================================
UPDATE assets
SET
    properties = jsonb_set(
        COALESCE(properties, '{}'),
        '{aliases}',
        COALESCE(properties->'aliases', '[]'::jsonb) || to_jsonb(name)
    ),
    name = LOWER(RTRIM(TRIM(name), '.')),
    updated_at = NOW()
WHERE asset_type = 'host'
  AND name !~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
  AND (name != LOWER(RTRIM(TRIM(name), '.'))
       OR name LIKE '%.');

-- ============================================================
-- Step 3: Normalize repository names
-- ============================================================
UPDATE assets
SET
    properties = jsonb_set(
        COALESCE(properties, '{}'),
        '{aliases}',
        COALESCE(properties->'aliases', '[]'::jsonb) || to_jsonb(name)
    ),
    name = LOWER(
        RTRIM(
            REGEXP_REPLACE(
                REGEXP_REPLACE(
                    REGEXP_REPLACE(TRIM(name), '^https?://', ''),
                    '^git@([^:]+):', '\1/'
                ),
                '\.git$', ''
            ),
            '/'
        )
    ),
    updated_at = NOW()
WHERE asset_type IN ('repository', 'code_repo')
  AND (
    name ~ '^https?://'
    OR name ~ '^git@'
    OR name ~ '\.git$'
    OR name != LOWER(name)
  );

-- ============================================================
-- Step 4: Detect duplicates and populate review queue
-- ============================================================
INSERT INTO asset_dedup_review (
    tenant_id, normalized_name, asset_type,
    keep_asset_id, keep_asset_name, keep_finding_count,
    merge_asset_ids, merge_asset_names, merge_finding_count,
    status
)
SELECT
    d.tenant_id,
    d.normalized_name,
    d.asset_type,
    d.ids[1],
    d.names[1],
    d.finding_counts[1],
    d.ids[2:],
    d.names[2:],
    COALESCE((SELECT SUM(x) FROM unnest(d.finding_counts[2:]) AS x), 0),
    'pending'
FROM (
    SELECT
        tenant_id,
        asset_type,
        name AS normalized_name,
        array_agg(id ORDER BY finding_count DESC, created_at ASC) AS ids,
        array_agg(name ORDER BY finding_count DESC, created_at ASC) AS names,
        array_agg(finding_count ORDER BY finding_count DESC, created_at ASC) AS finding_counts
    FROM assets
    WHERE asset_type IN ('domain', 'subdomain', 'host', 'repository', 'code_repo')
    GROUP BY tenant_id, asset_type, name
    HAVING COUNT(*) > 1
) d
ON CONFLICT DO NOTHING;
