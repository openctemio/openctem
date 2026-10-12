### Changed: state history and service lists page with page / per_page

- `GET /state-history` (and its views: appearances, disappearances,
  newly-exposed, exposure-changes, shadow-it, compliance),
  `GET /assets/{id}/state-history`, `GET /services` and
  `GET /services/public` take `page` and `per_page` (max 100) and return
  the list envelope (`data`, `total`, `page`, `per_page`, `total_pages`).
  `limit` and `offset` are no longer read (they allowed 1000 rows per
  request). The web's "What changed" page and the asset rename history use
  the new parameters.
