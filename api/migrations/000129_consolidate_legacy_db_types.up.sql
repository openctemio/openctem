-- Consolidate legacy DB-only types that exist in asset_types table
-- but differ from code-level types.
-- These types came from the configurable asset_types table (migration 037/060)
-- and don't match the code-level AssetType constants.

-- ip → ip_address (same concept, different name)
UPDATE assets SET sub_type = 'ip', asset_type = 'ip_address'
    WHERE asset_type = 'ip' AND sub_type IS NULL;
UPDATE assets SET asset_type = 'ip_address'
    WHERE asset_type = 'ip';

-- port → service (open port is a discovered service)
UPDATE assets SET sub_type = 'port', asset_type = 'service'
    WHERE asset_type = 'port' AND sub_type IS NULL;
UPDATE assets SET asset_type = 'service'
    WHERE asset_type = 'port';

-- ssl_certificate → certificate
UPDATE assets SET sub_type = 'ssl', asset_type = 'certificate'
    WHERE asset_type = 'ssl_certificate' AND sub_type IS NULL;
UPDATE assets SET asset_type = 'certificate'
    WHERE asset_type = 'ssl_certificate';

-- container_image → container
UPDATE assets SET sub_type = 'image', asset_type = 'container'
    WHERE asset_type = 'container_image' AND sub_type IS NULL;
UPDATE assets SET asset_type = 'container'
    WHERE asset_type = 'container_image';

-- server → host
UPDATE assets SET sub_type = 'server', asset_type = 'host'
    WHERE asset_type = 'server' AND sub_type IS NULL;
UPDATE assets SET asset_type = 'host'
    WHERE asset_type = 'server';
