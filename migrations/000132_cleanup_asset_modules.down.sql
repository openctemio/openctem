-- =============================================================================
-- Rollback 000132: Restore modules to pre-consolidation state
-- =============================================================================

-- Re-activate deprecated modules
UPDATE modules SET is_active = true, release_status = 'released'
WHERE id IN ('assets.cloud_resources', 'assets.serverless');

UPDATE modules SET is_active = true, release_status = 'coming_soon'
WHERE id IN ('assets.kubernetes', 'assets.ports');

-- web_apps and compute stay deprecated (were already deprecated before 000132)

-- Restore original names
UPDATE modules SET name = 'Container Images' WHERE id = 'assets.containers';
UPDATE modules SET name = 'Data Stores' WHERE id = 'assets.data_stores';

-- Downgrade Subdomains back to coming_soon
UPDATE modules SET release_status = 'coming_soon' WHERE id = 'assets.subdomains';

-- Remove Identity module (clean FK references first)
DELETE FROM tenant_modules WHERE module_id = 'assets.identity';
DELETE FROM modules WHERE id = 'assets.identity';
