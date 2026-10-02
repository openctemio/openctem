-- =============================================================================
-- Migration 000060: Schema Fixes (Audit Findings)
-- OpenCTEM OSS Edition
-- =============================================================================
-- Addresses issues found during comprehensive migration audit (new vs old):
--
-- CRITICAL:
--   1. findings.fingerprint VARCHAR(64) → VARCHAR(512)
--   2. exposure_events.fingerprint VARCHAR(64) → VARCHAR(512)
--   3. asset_owners: unique partial indexes (prevent duplicate ownership)
--   4. asset_owners: CHECK constraint (at least one owner must be set)
--   5. target_asset_type_mappings: fix ip_address → ip
--   6. asset_types: add 'unclassified' + missing types
--
-- HIGH:
--   7. asset_components: null-safe UNIQUE index for branch_id
--   8. workflow_edges: UNIQUE + self-reference CHECK
--   9. workflow_node_runs: UNIQUE constraint
--
-- NOTE: tool_capabilities linking moved to 000055 (links ALL built-in tools)
-- =============================================================================

-- =============================================================================
-- 1 & 2. Widen fingerprint columns (CRITICAL)
-- =============================================================================
-- SHA-256 alone is 64 chars, but composite fingerprints, SARIF-style
-- fingerprints, and custom hashing schemes can exceed that.
-- Old project used VARCHAR(512).

ALTER TABLE findings ALTER COLUMN fingerprint TYPE VARCHAR(512);
ALTER TABLE exposure_events ALTER COLUMN fingerprint TYPE VARCHAR(512);

-- =============================================================================
-- 3. Asset Owners: Unique Partial Indexes (CRITICAL)
-- =============================================================================
-- Prevent duplicate group→asset and user→asset ownership rows.
-- Old project had these; new project was missing them.

CREATE UNIQUE INDEX IF NOT EXISTS idx_uq_asset_owners_asset_group
    ON asset_owners(asset_id, group_id) WHERE group_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_uq_asset_owners_asset_user
    ON asset_owners(asset_id, user_id) WHERE user_id IS NOT NULL;

-- =============================================================================
-- 4. Asset Owners: At Least One Owner (CRITICAL)
-- =============================================================================
-- Either group_id or user_id must be set. Clean up invalid rows first.

DELETE FROM asset_owners WHERE group_id IS NULL AND user_id IS NULL;

ALTER TABLE asset_owners
    ADD CONSTRAINT chk_asset_owners_has_owner
    CHECK (group_id IS NOT NULL OR user_id IS NOT NULL);

-- =============================================================================
-- 5. Asset Types: Add 'unclassified' + missing types (CRITICAL)
-- =============================================================================
-- 'unclassified' is required by smart filtering logic (always skipped).
-- Other types are referenced by target_asset_type_mappings (000031) but
-- were missing from asset_types seed (000037).

-- Add 'recon' category for scanner-discovered assets
INSERT INTO asset_type_categories (code, name, description, icon, display_order)
VALUES ('recon', 'Reconnaissance', 'Assets discovered through scanning and reconnaissance', 'search', 7)
ON CONFLICT (code) DO NOTHING;

INSERT INTO asset_types (code, name, description, category_id, icon, color, display_order, is_discoverable, is_scannable, is_system) VALUES
-- Special
('unclassified', 'Unclassified', 'Asset with unknown or unclassified type',
    (SELECT id FROM asset_type_categories WHERE code = 'other'), 'help-circle', '#9CA3AF', 100, FALSE, FALSE, TRUE),

-- Recon-discovered types
('discovered_url', 'Discovered URL', 'URL found during reconnaissance crawling',
    (SELECT id FROM asset_type_categories WHERE code = 'recon'), 'link', '#06B6D4', 70, TRUE, TRUE, TRUE),
('http_service', 'HTTP Service', 'Running HTTP/HTTPS service detected on a host',
    (SELECT id FROM asset_type_categories WHERE code = 'recon'), 'globe', '#0EA5E9', 71, TRUE, TRUE, TRUE),
('open_port', 'Open Port', 'Open network port discovered on a host',
    (SELECT id FROM asset_type_categories WHERE code = 'recon'), 'plug', '#8B5CF6', 72, TRUE, TRUE, TRUE),

-- Infrastructure
('server', 'Server', 'Physical or virtual server',
    (SELECT id FROM asset_type_categories WHERE code = 'infrastructure'), 'server', '#64748B', 7, FALSE, TRUE, TRUE),

-- Cloud networking/infra
('vpc', 'VPC', 'Virtual Private Cloud network',
    (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'cloud', '#7C3AED', 35, FALSE, TRUE, TRUE),
('subnet', 'Subnet', 'Network subnet within a VPC',
    (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'git-branch', '#A78BFA', 36, FALSE, TRUE, TRUE),
('firewall', 'Firewall', 'Firewall or security group',
    (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'shield', '#EF4444', 37, FALSE, TRUE, TRUE),
('load_balancer', 'Load Balancer', 'Load balancer or reverse proxy',
    (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'split', '#F59E0B', 38, FALSE, TRUE, TRUE),
('compute', 'Compute Instance', 'Virtual machine or compute instance',
    (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'server', '#10B981', 39, FALSE, TRUE, TRUE),

-- Container types
('container', 'Container', 'Running container instance',
    (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'box', '#06B6D4', 40, TRUE, TRUE, TRUE),
('container_registry', 'Container Registry', 'Container image registry (Docker Hub, ECR, etc.)',
    (SELECT id FROM asset_type_categories WHERE code = 'code'), 'archive', '#A855F7', 23, FALSE, TRUE, TRUE),

-- Cloud storage
('storage', 'Storage', 'Cloud storage resource (S3, GCS, Azure Blob, etc.)',
    (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'hard-drive', '#F97316', 41, FALSE, TRUE, TRUE),
('s3_bucket', 'S3 Bucket', 'Amazon S3 bucket or compatible object storage',
    (SELECT id FROM asset_type_categories WHERE code = 'cloud'), 'archive', '#F97316', 42, FALSE, TRUE, TRUE),

-- Identity
('certificate', 'Certificate', 'TLS/SSL or code-signing certificate',
    (SELECT id FROM asset_type_categories WHERE code = 'identity'), 'award', '#059669', 53, FALSE, TRUE, TRUE)

ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    category_id = EXCLUDED.category_id,
    icon = EXCLUDED.icon,
    color = EXCLUDED.color,
    display_order = EXCLUDED.display_order,
    is_discoverable = EXCLUDED.is_discoverable,
    is_scannable = EXCLUDED.is_scannable,
    updated_at = NOW();

-- =============================================================================
-- 6. Target Asset Type Mappings: Fix Stale References (CRITICAL)
-- =============================================================================
-- asset_types has code 'ip', but mappings referenced 'ip_address'.
-- asset_types has 'serverless_function', but mappings referenced 'serverless'.

UPDATE target_asset_type_mappings
SET asset_type = 'ip', updated_at = NOW()
WHERE asset_type = 'ip_address';

UPDATE target_asset_type_mappings
SET asset_type = 'serverless_function', updated_at = NOW()
WHERE asset_type = 'serverless';

-- =============================================================================
-- =============================================================================
-- 7. Asset Components: Null-Safe UNIQUE Index (HIGH)
-- =============================================================================
-- PostgreSQL treats NULLs as distinct in UNIQUE constraints, so two rows
-- with the same (tenant, asset, name, version) but branch_id=NULL would
-- both be allowed. Old project used COALESCE trick for null-safe uniqueness.

ALTER TABLE asset_components DROP CONSTRAINT IF EXISTS unique_component;

CREATE UNIQUE INDEX IF NOT EXISTS idx_uq_asset_component
    ON asset_components(
        tenant_id, asset_id, name, version,
        COALESCE(branch_id, '00000000-0000-0000-0000-000000000000')
    );

-- =============================================================================
-- 9. Workflow Edges: UNIQUE + Self-Reference CHECK (HIGH)
-- =============================================================================
-- Prevent duplicate edges between same node pair within a workflow.
-- Prevent self-loops (source_node_key → same node).

CREATE UNIQUE INDEX IF NOT EXISTS idx_uq_workflow_edge
    ON workflow_edges(workflow_id, source_node_key, target_node_key);

ALTER TABLE workflow_edges
    ADD CONSTRAINT chk_workflow_edge_no_self_loop
    CHECK (source_node_key <> target_node_key);

-- =============================================================================
-- 10. Workflow Node Runs: UNIQUE Constraint (HIGH)
-- =============================================================================
-- Each node should only execute once per workflow run.

CREATE UNIQUE INDEX IF NOT EXISTS idx_uq_workflow_node_run
    ON workflow_node_runs(workflow_run_id, node_key);
