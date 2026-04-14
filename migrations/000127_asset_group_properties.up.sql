-- Add properties JSONB to asset_groups for storing segment metadata
-- (CIDR, VLAN ID, gateway, DNS servers, etc.)
ALTER TABLE asset_groups ADD COLUMN IF NOT EXISTS properties JSONB DEFAULT '{}';

-- Add group_type to distinguish regular groups from network segments
ALTER TABLE asset_groups ADD COLUMN IF NOT EXISTS group_type VARCHAR(30) DEFAULT 'manual';
-- Values: manual (user-created), dynamic (rule-based), network_segment, business_unit

COMMENT ON COLUMN asset_groups.properties IS 'Flexible metadata: CIDR, VLAN, gateway for network segments; custom fields for other group types';
COMMENT ON COLUMN asset_groups.group_type IS 'Group classification: manual, dynamic, network_segment, business_unit';
