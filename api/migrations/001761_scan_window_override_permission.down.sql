-- Back to scans:freeze:override.

INSERT INTO permissions (id, module_id, name, description, is_active, created_at)
SELECT 'scans:freeze:override', p.module_id, 'Override Scan Freeze Windows',
       'Start a scan by hand while a freeze window is active (audited)', p.is_active, p.created_at
FROM permissions p WHERE p.id = 'scans:windows:override'
ON CONFLICT (id) DO NOTHING;

UPDATE role_permissions SET permission_id = 'scans:freeze:override' WHERE permission_id = 'scans:windows:override';
UPDATE api_keys SET scopes = array_replace(scopes, 'scans:windows:override', 'scans:freeze:override')
WHERE 'scans:windows:override' = ANY(scopes);
DELETE FROM permissions WHERE id = 'scans:windows:override';
