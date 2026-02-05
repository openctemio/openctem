-- =============================================================================
-- Migration 031: Target Asset Type Mappings (Down)
-- =============================================================================

DROP FUNCTION IF EXISTS get_compatible_asset_types(TEXT[]);
DROP FUNCTION IF EXISTS can_tool_scan_asset_type(TEXT[], TEXT);

DROP TABLE IF EXISTS target_asset_type_mappings;

