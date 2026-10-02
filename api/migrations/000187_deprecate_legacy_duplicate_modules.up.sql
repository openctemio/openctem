-- Deprecate 5 legacy single-word module rows seeded in migration 000004 that
-- were later superseded by a more specific vocabulary the presets, dependency
-- graph, route gates and UI sidebar actually use. They lingered as `released`
-- rows, so they rendered as duplicate, dead toggles in Settings → Modules and
-- (for `pipelines`) even 403'd real routes for subscribed tenants.
--
--   scope      → scope_config            (attack_surface:scope:read)
--   secrets    → credentials             (leaked-credential monitoring)
--   sources    → template_sources        (scans:sources:read)
--   webhooks   → integrations.webhooks   (integrations:webhooks:read)
--   pipelines  → scan_pipelines          (route gate realigned in routes.go)
--
-- None are referenced by any preset, dependency edge, or (after the routes.go
-- fix that ships with this migration) route gate. Marking them inactive +
-- deprecated removes them from ListActiveModules and the module picker without
-- deleting the rows (reversible, and any stray tenant_modules overrides remain
-- harmless).

UPDATE modules
SET is_active = FALSE,
    release_status = 'deprecated'
WHERE id IN ('scope', 'secrets', 'sources', 'webhooks', 'pipelines');
