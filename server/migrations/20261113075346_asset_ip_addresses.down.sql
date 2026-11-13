-- Removes the derived address table (it holds nothing that is not in
-- assets). The range filters of this release read it: roll back the code
-- with it.
DROP TRIGGER IF EXISTS trg_assets_ip_addresses_update ON assets;
DROP TRIGGER IF EXISTS trg_assets_ip_addresses_insert ON assets;
DROP FUNCTION IF EXISTS asset_ip_addresses_update();
DROP FUNCTION IF EXISTS asset_ip_addresses_insert();
DROP TABLE IF EXISTS asset_ip_addresses;
DROP FUNCTION IF EXISTS asset_recorded_addresses(text, text, jsonb);
