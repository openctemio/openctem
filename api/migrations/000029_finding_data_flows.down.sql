-- =============================================================================
-- Migration 029: Finding Data Flows + Scanner Templates (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS update_scanner_templates_updated_at ON scanner_templates;
DROP TRIGGER IF EXISTS update_template_sources_updated_at ON template_sources;
DROP TABLE IF EXISTS scan_profile_template_sources;
DROP TABLE IF EXISTS scanner_templates;
DROP TABLE IF EXISTS template_sources;
DROP TABLE IF EXISTS finding_flow_locations;
DROP TABLE IF EXISTS finding_data_flows;
