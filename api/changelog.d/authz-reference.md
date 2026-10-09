### Added: a generated authorization reference, and refusals that name what is missing

- `go run ./cmd/gen-authz-docs` builds the authorization reference from the
  source (permission catalog, built-in roles, role templates, route gates,
  module gates, step-up, the data-scope registry, personas and recommended
  teams). `make contract` writes `web/src/config/authz-matrix.json` (generated,
  not committed); `make authz-docs DIR=...` writes the role and permission
  matrix, the personas page and one page per feature for the documentation site.
- CI fails on a route that belongs to no feature, or that has neither a gate
  nor an allowlist reason (`TestEveryRouteIsClassified`).
- A 403 from a permission or team-role gate now carries
  `details.missing_permissions`, `details.any_of` or `details.required_role`.
  The code and message are unchanged; data-scope refusals still answer 404.
