### Added: precomputed exploration figures

- New table `exploration_rollups` (migration `exploration_rollups`), recomputed by the exploration job
  after every pass: live leads by state, leads settled and proven or refuted in the last 30 days,
  dispatches, the share opened by rules, the median time to a verdict and the last step.
- `GET /api/v1/exploration/summary` and `POST /api/v1/exploration/summary/refresh` (`assets:read`,
  Refresh now at most once a minute) return them with their freshness to callers who see the whole
  organization or view organization dashboards; any other member gets live counts within their data
  scope.
