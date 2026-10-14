### Added: coverage gap alerts

- The asset coverage loop alerts an organization's administrators (in-app,
  type `coverage_gap`) and its integrations (event `coverage_gap`, on by
  default for new integrations) when assets go without a capability their
  type needs for more than twice its cadence, when a capability produced
  none of its expected output over at least 20 inputs in a day (a broken or
  blocked tool), or when a capability failed 3 times in a row. At most one
  alert per capability and kind every 20 hours.
- Operators get fleet-wide aggregates without organization labels:
  `openctem_asset_coverage_gap_pairs{capability}` and
  `openctem_asset_coverage_alerts_total{kind,capability}`.
