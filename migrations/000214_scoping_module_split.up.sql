-- =============================================================================
-- Migration 000214: Split scoping features into independently-toggleable modules
--
-- Before this migration, three shipped Scoping features shared a module with a
-- broader one, so a tenant could not toggle them on their own:
--
--   - Business Units  -> gated by nothing at the API, sidebar-bound to scope_config
--   - Crown Jewels    -> sidebar-bound to scope_config (view over core assets)
--   - Threat Model    -> gated by nothing at the API, sidebar-bound to attack_surface
--
-- This back-fills their own module rows so the Settings > Modules screen lists
-- them and admins can enable/disable each independently. The companion Go
-- constants (ModuleBusinessUnits / ModuleCrownJewels / ModuleThreatModel),
-- catalogue entries, dependency edges and presets land in the same PR.
--
-- BACK-COMPAT: rows are seeded is_active=true / release_status='released'. The
-- tenant enabled-module set is "all active modules minus explicitly-disabled",
-- so every existing tenant with no override keeps these three features on. Any
-- tenant subscribed to a bundle gets them via the preset additions in the same
-- PR (they are appended to every preset that already enabled scope_config /
-- attack_surface). ON CONFLICT DO NOTHING preserves operator customisations.
-- =============================================================================

BEGIN;

INSERT INTO modules (id, slug, name, description, icon, category, display_order, is_active, is_core, release_status) VALUES
    ('business_units', 'business-units', 'Business Units', 'Organisational units that group assets for ownership, criticality and reporting', 'Building2', 'scoping', 11, true, false, 'released'),
    ('crown_jewels',   'crown-jewels',   'Crown Jewels',   'Business-critical assets flagged for heightened prioritisation and monitoring',   'Crown',     'scoping', 12, true, false, 'released'),
    ('threat_model',   'threat-model',   'Threat Model',   'Continuous threat modelling derived from the asset graph and findings',            'Crosshair', 'scoping', 13, true, false, 'released')
ON CONFLICT (id) DO NOTHING;

COMMIT;
