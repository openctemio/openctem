-- =============================================================================
-- Migration 000131: Normalize network sub_types
-- =============================================================================
-- Simplify switch sub_types: core_switch, access_switch → switch
-- Preserve original value in metadata.device_role for detailed display
-- =============================================================================

-- Step 1: Copy original sub_type to metadata.device_role (if not already set)
UPDATE assets
SET properties = jsonb_set(
  COALESCE(properties, '{}'::jsonb),
  '{device_role}',
  to_jsonb(sub_type)
)
WHERE asset_type = 'network'
  AND sub_type IN ('core_switch', 'access_switch')
  AND (properties IS NULL OR NOT properties ? 'device_role');

-- Step 2: Normalize sub_types
UPDATE assets SET sub_type = 'switch'       WHERE sub_type IN ('core_switch', 'access_switch');
UPDATE assets SET sub_type = 'wireless_ap'  WHERE sub_type = 'wireless_ap'; -- no change, just documenting
