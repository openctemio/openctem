### Added: the Web surface page

- Assets > Web surface (`/assets/web`): origins with their coverage gap, endpoints (method and path template) with a
  detail drawer listing parameter names (never values), path patterns across origins, and the change feed.
- Endpoints under a scope exclusion show as "Excluded, untested" with a link to the exclusions, so no findings there
  is not read as safe. Sensitive-path catalog matches and endpoints answering without authentication are flagged.
- Paths render as text and are never opened from the page. `/assets/discovered-urls` now opens the endpoint list.
  Design: RFC-056.
