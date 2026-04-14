-- Reverse: convert ip_addresses array back to single ip string (take first element)
UPDATE assets
SET properties = (
    properties
    || jsonb_build_object('ip', (properties->'ip_addresses'->>0))
) - 'ip_addresses'
WHERE asset_type = 'host'
  AND properties->'ip_addresses' IS NOT NULL;
