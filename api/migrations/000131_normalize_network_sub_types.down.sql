-- Rollback: restore original sub_type from metadata.device_role
UPDATE assets SET sub_type = properties->>'device_role'
WHERE asset_type = 'network'
  AND sub_type = 'switch'
  AND properties ? 'device_role'
  AND properties->>'device_role' IN ('core_switch', 'access_switch');
