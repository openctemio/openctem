-- =============================================================================
-- Migration 000132: Cleanup asset modules after type consolidation
-- =============================================================================
-- Codifies module changes from the 33→15 type consolidation:
-- 1. Deprecate redundant sub-modules
-- 2. Rename for UI consistency
-- 3. Add new Identity module
-- 4. Clean orphan tenant_modules overrides
-- Idempotent: safe to re-run on dirty recovery.
-- =============================================================================

-- Step 1: Deprecate redundant modules
UPDATE modules SET is_active = false, release_status = 'deprecated'
WHERE id IN (
  'assets.cloud_resources',  -- merged into cloud-accounts + storage
  'assets.kubernetes',       -- merged into containers (Containers & K8s)
  'assets.serverless',       -- merged into hosts (sub_type=serverless)
  'assets.ports',            -- merged into services (sub_type=open_port)
  'assets.web_apps',         -- merged into websites (already deprecated)
  'assets.compute'           -- merged into hosts (already deprecated)
);

-- Step 2: Rename for consistency with UI
UPDATE modules SET name = 'Containers & K8s' WHERE id = 'assets.containers';
UPDATE modules SET name = 'Storage' WHERE id = 'assets.data_stores';

-- Step 3: Upgrade Subdomains (has real data)
UPDATE modules SET release_status = 'released' WHERE id = 'assets.subdomains';

-- Step 4: Add Identity module
INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status, parent_module_id)
VALUES ('assets.identity', 'identity', 'Identity & Access', 'IAM users, roles, service accounts', 'shield-check', 'discovery', 85, true, false, 'released', 'assets')
ON CONFLICT (id) DO UPDATE SET name = 'Identity & Access', is_active = true, release_status = 'released', slug = 'identity';

-- Step 5: Clean orphan tenant_modules for deprecated modules
DELETE FROM tenant_modules
WHERE module_id IN (
  'assets.cloud_resources', 'assets.kubernetes', 'assets.serverless',
  'assets.ports', 'assets.web_apps', 'assets.compute'
);
