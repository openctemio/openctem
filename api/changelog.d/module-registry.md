### Changed: one declarative module registry

- `configs/modules.yaml` declares every module: presentation, core flag, release,
  read permission, dependencies, and the REST routes, MCP tools and background jobs it
  owns. `make generate-modules` writes the Go catalog and the web constants; migration
  001460 writes the `modules` rows from it; CI fails on drift (`make modules-check`).
- Coverage tests fail when a route, an MCP tool or a job does not follow the registry.
- Fixed with it: relationship suggestions (`/api/v1/relationships/suggestions`) follow
  the `relationships` module, and the scope join background pass skips organizations with
  `attack_surface` off.
