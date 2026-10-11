### Fixed: asset counts, tags and asset details answered 404

- The asset component routes were mounted at `/api/v1/assets/{id}`, which captured every one-segment asset route (`/stats`, `/tags`, `/facets`, `/overview`, `/changes` and `GET /assets/{id}`) and answered 404: the inventory KPI strip showed 0 while the list below had rows. Each component sub-path now has its own group.
