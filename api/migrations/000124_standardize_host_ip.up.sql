-- Standardize host IP storage: properties.ip (string) → properties.ip_addresses (array)
-- This migration converts all host assets that have properties.ip (single string)
-- to the standard properties.ip_addresses (array) format.
--
-- Before: { "ip": "10.0.1.5", ... }
-- After:  { "ip_addresses": ["10.0.1.5"], "hostname": "...", ... }
--
-- The old "ip" key is removed after migration to avoid ambiguity.

-- Step 1: For hosts that have properties.ip but NOT properties.ip_addresses,
-- create ip_addresses array from the single ip value.
UPDATE assets
SET properties = (
    properties
    -- Add ip_addresses array with the single IP
    || jsonb_build_object('ip_addresses', jsonb_build_array(properties->>'ip'))
    -- Remove the old "ip" key
) - 'ip'
WHERE asset_type = 'host'
  AND properties->>'ip' IS NOT NULL
  AND properties->'ip_addresses' IS NULL;

-- Step 2: For hosts that have BOTH properties.ip AND properties.ip_addresses,
-- merge the single ip into the array (if not already present) and remove "ip" key.
UPDATE assets
SET properties = (
    CASE
        WHEN NOT (properties->'ip_addresses' ? (properties->>'ip'))
        THEN properties || jsonb_build_object(
            'ip_addresses',
            properties->'ip_addresses' || jsonb_build_array(properties->>'ip')
        )
        ELSE properties
    END
) - 'ip'
WHERE asset_type = 'host'
  AND properties->>'ip' IS NOT NULL
  AND properties->'ip_addresses' IS NOT NULL;

-- Step 3: For hosts named as IP (e.g., "10.0.1.5") that don't have ip_addresses yet,
-- create the array from the asset name.
UPDATE assets
SET properties = properties || jsonb_build_object('ip_addresses', jsonb_build_array(name))
WHERE asset_type = 'host'
  AND properties->'ip_addresses' IS NULL
  AND name ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$';
