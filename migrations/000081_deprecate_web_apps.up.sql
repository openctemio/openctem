-- =============================================================================
-- Migration 000081: Deprecate Web Applications (redundant with Websites)
-- =============================================================================
-- "Web Applications" (assets.web_apps / web_application) and "Websites"
-- (assets.websites / website) are functionally identical:
--   - Same category (application)
--   - Same description ("Web application management")
--   - Same URL validation pattern (^https?://)
--   - Same scanner target mapping (url)
--   - Only "Websites" has a frontend implementation
--
-- This migration:
-- 1. Migrates existing web_application assets → website
-- 2. Deprecates the assets.web_apps module
-- 3. Deactivates the web_application asset type
-- 4. Deactivates the web_application target mapping
-- =============================================================================

-- Step 1: Migrate existing assets from web_application → website
-- This ensures no data loss before deactivating the type
UPDATE assets
SET asset_type = 'website', updated_at = NOW()
WHERE asset_type = 'web_application';

-- Step 2: Deprecate the module
UPDATE modules
SET release_status = 'deprecated', is_active = false, updated_at = NOW()
WHERE id = 'assets.web_apps';

-- Step 3: Deactivate the asset type (keep row for historical reference)
UPDATE asset_types
SET is_active = false, updated_at = NOW()
WHERE code = 'web_application';

-- Step 4: Deactivate the target mapping
UPDATE target_asset_type_mappings
SET is_active = false, updated_at = NOW()
WHERE asset_type = 'web_application';

-- Step 5: Clear module_id reference from the deactivated asset type
UPDATE asset_types
SET module_id = NULL, updated_at = NOW()
WHERE code = 'web_application';
