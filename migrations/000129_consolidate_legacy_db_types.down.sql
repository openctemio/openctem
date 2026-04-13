-- Restore legacy types from sub_type
UPDATE assets SET asset_type = 'ip' WHERE asset_type = 'ip_address' AND sub_type = 'ip';
UPDATE assets SET asset_type = 'port' WHERE asset_type = 'service' AND sub_type = 'port';
UPDATE assets SET asset_type = 'ssl_certificate' WHERE asset_type = 'certificate' AND sub_type = 'ssl';
UPDATE assets SET asset_type = 'container_image' WHERE asset_type = 'container' AND sub_type = 'image';
UPDATE assets SET asset_type = 'server' WHERE asset_type = 'host' AND sub_type = 'server';
