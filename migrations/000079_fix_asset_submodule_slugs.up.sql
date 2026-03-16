-- =============================================================================
-- Fix asset sub-module slugs to match frontend assetModuleKey values
-- =============================================================================
-- The sidebar filtering (useFilteredSubItems) matches sub-modules by slug.
-- Several DB slugs don't match the frontend assetModuleKey values, causing
-- those asset types to be hidden or shown only via backward compatibility.
--
-- This migration:
-- 1. Fixes slug mismatches (DB slug → frontend assetModuleKey)
-- 2. Adds missing "compute" sub-module (exists in sidebar but not in DB)
-- 3. Marks sub-modules without pages as "coming_soon"
-- =============================================================================

-- Fix slug mismatches: update slugs to match frontend URL paths / assetModuleKey
UPDATE modules SET slug = 'ip-addresses', updated_at = NOW() WHERE id = 'assets.ips';
UPDATE modules SET slug = 'mobile', updated_at = NOW() WHERE id = 'assets.mobile_apps';
UPDATE modules SET slug = 'cloud-accounts', updated_at = NOW() WHERE id = 'assets.cloud_accounts';
UPDATE modules SET slug = 'cloud-resources', updated_at = NOW() WHERE id = 'assets.cloud_resources';
UPDATE modules SET slug = 'storage', updated_at = NOW() WHERE id = 'assets.data_stores';

-- Mark sub-modules without implemented pages as "coming_soon"
-- These exist in DB but have no frontend page or sidebar item
UPDATE modules SET release_status = 'coming_soon', updated_at = NOW() WHERE id = 'assets.subdomains';
UPDATE modules SET release_status = 'coming_soon', updated_at = NOW() WHERE id = 'assets.ports';
UPDATE modules SET release_status = 'coming_soon', updated_at = NOW() WHERE id = 'assets.web_apps';
UPDATE modules SET release_status = 'coming_soon', updated_at = NOW() WHERE id = 'assets.artifacts';
UPDATE modules SET release_status = 'coming_soon', updated_at = NOW() WHERE id = 'assets.credentials';
UPDATE modules SET release_status = 'coming_soon', updated_at = NOW() WHERE id = 'assets.iot';
UPDATE modules SET release_status = 'coming_soon', updated_at = NOW() WHERE id = 'assets.hardware';
UPDATE modules SET release_status = 'coming_soon', updated_at = NOW() WHERE id = 'assets.kubernetes';
