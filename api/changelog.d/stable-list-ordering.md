### Fixed: list pages no longer repeat or skip rows that tie on the sort key

- The shared sort helper now ends every ORDER BY with an `id` tie-breaker (in the direction of the last sort key), and the default sorts of the asset, finding, exposure, catalog vulnerability and repository lists end in `id`. Paging through rows that share a `created_at` or severity could previously return a row twice or never.
