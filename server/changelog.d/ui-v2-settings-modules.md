### Changed: Settings > Modules follows the settings page pattern (redesign branch)

- `/settings/modules` is drawn with the shared settings parts: the title with Reset to defaults, the view-only note,
  search and the On / Off / Unavailable filter, then one section per group with its "N of M on" count and the
  modules as rows divided by hairlines. Who changed the modules last sits beside the first section's title.
- Loading and a failed load look as on every settings page (the failed load offers Retry and never shows an empty
  list).
- Turning modules on or off, the dependency preview, the confirmation of dependents, Reset to defaults, the lock of
  each module with the reason its server state maps to, permissions and every API call are unchanged.
- Docs: none (the page keeps its functions; the look is described in web/docs/ui-style-contract.md, "Settings pages")
