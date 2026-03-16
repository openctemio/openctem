-- Revert asset sub-module slug fixes (back to original 000004 values)
UPDATE modules SET slug = 'ips', updated_at = NOW() WHERE id = 'assets.ips';
UPDATE modules SET slug = 'mobile_apps', updated_at = NOW() WHERE id = 'assets.mobile_apps';
UPDATE modules SET slug = 'cloud_accounts', updated_at = NOW() WHERE id = 'assets.cloud_accounts';
UPDATE modules SET slug = 'cloud_resources', updated_at = NOW() WHERE id = 'assets.cloud_resources';
UPDATE modules SET slug = 'data_stores', updated_at = NOW() WHERE id = 'assets.data_stores';

-- Revert coming_soon status back to released
UPDATE modules SET release_status = 'released', updated_at = NOW() WHERE id IN (
    'assets.subdomains', 'assets.ports', 'assets.web_apps',
    'assets.artifacts', 'assets.credentials', 'assets.iot',
    'assets.hardware', 'assets.kubernetes'
);
