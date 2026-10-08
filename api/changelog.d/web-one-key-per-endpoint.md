### Changed: the web console caches each endpoint once, and an organization switch clears the cache

- Pages that read the same endpoint (the dashboard, threat intel, validation,
  scoping, exposures, sidebar badges) now share one cached answer instead of
  fetching it again under a second cache key.
- Switching organization drops every cached answer before reloading, so no
  data of the previous organization stays on screen while the new one loads.
