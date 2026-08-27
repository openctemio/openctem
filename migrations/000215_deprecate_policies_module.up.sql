-- Deprecate the `policies` module row seeded in migration 000004.
--
-- `policies` shipped with a catalogue row, a `findings:policies:*` permission
-- family (000005) and a soft dependency edge, but it never grew any routes and
-- has no real sidebar navigation. It therefore rendered as a dead toggle in
-- Settings → Modules that gates and shows nothing — the same class of cruft
-- migration 000187 retired for scope/secrets/sources/webhooks/pipelines.
--
-- Mark it inactive + deprecated so it drops out of ListActiveModules and the
-- module picker without deleting the row (reversible; any stray tenant_modules
-- overrides remain harmless). The Go constant ModulePolicies and its
-- ModulePermissionMapping entry are kept so historic permission lookups still
-- resolve; it is removed from every preset and from the dependency graph in the
-- same PR, and added to legacyDuplicateModuleIDs so the "CTEM Full = every real
-- module" invariant continues to exclude it.

UPDATE modules
SET is_active = FALSE,
    release_status = 'deprecated'
WHERE id = 'policies';
