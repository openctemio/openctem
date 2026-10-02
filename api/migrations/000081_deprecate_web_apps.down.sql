-- Rollback: Re-activate web_application asset type and module
-- Note: Cannot automatically un-migrate assets back to web_application

UPDATE target_asset_type_mappings
SET is_active = true
WHERE asset_type = 'web_application';

UPDATE asset_types
SET is_active = true, module_id = 'assets.web_apps', updated_at = NOW()
WHERE code = 'web_application';

UPDATE modules
SET release_status = 'coming_soon', is_active = true, updated_at = NOW()
WHERE id = 'assets.web_apps';
