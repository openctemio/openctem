### Added: the dashboard loads with one request

- `GET /dashboard/overview` returns the CTEM dashboard's reads in one response,
  each part keyed by its endpoint's URL and answered through that endpoint's own
  permission, module and data-scope checks. The dashboard sends one request
  instead of twelve.
