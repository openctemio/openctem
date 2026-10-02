-- =============================================================================
-- Migration 044: Global Components, Component Licenses, Access Control (Down)
-- =============================================================================

DROP TRIGGER IF EXISTS trigger_assignment_rules_updated_at ON assignment_rules;
DROP TRIGGER IF EXISTS trigger_components_updated_at ON components;

DROP TABLE IF EXISTS assignment_rules;
DROP TABLE IF EXISTS group_permissions;
DROP TABLE IF EXISTS component_licenses;

-- Restore findings FK to asset_components
DO $$ BEGIN
    ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_component_id_fkey;
EXCEPTION WHEN undefined_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE findings ADD CONSTRAINT findings_component_id_fkey
        FOREIGN KEY (component_id) REFERENCES asset_components(id) ON DELETE SET NULL;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DROP TABLE IF EXISTS components;

-- Remove added constraints
DROP INDEX IF EXISTS uq_asset_components_asset_component_path;
ALTER TABLE licenses DROP CONSTRAINT IF EXISTS uq_licenses_spdx_id;
