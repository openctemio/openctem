### Added: batch reads for asset names and change counts

- `GET /assets` takes `ids` (comma-separated UUIDs, at most 100): one request
  for a set of assets, with the caller's data scope. The threat-model page
  resolves asset names with it instead of one request per asset.
- `GET /state-history/counts` returns the totals of the five "What changed"
  views in one response; the page sent five requests for them.
