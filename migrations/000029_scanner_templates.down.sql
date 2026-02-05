-- =============================================================================
-- Migration 000029: Scanner Templates (ROLLBACK)
-- =============================================================================

DROP TRIGGER IF EXISTS update_scanner_templates_updated_at ON scanner_templates;
DROP TRIGGER IF EXISTS update_template_sources_updated_at ON template_sources;
DROP TABLE IF EXISTS scan_profile_template_sources;
DROP TABLE IF EXISTS scanner_templates;
DROP TABLE IF EXISTS template_sources;
