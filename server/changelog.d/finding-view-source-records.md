### Changed: the finding page view carries the per-source records

- `GET /api/v1/findings/{id}/view` now includes the part for `GET /api/v1/findings/{id}/source-records`, so a hard load of the finding page makes four API requests again instead of five. The records pass the same tenant, data-scope and `sensors:read` checks as a direct call and are read only when the finding itself answered 200; if they fail alone, the view still answers and the page reads them itself. `GET /api/v1/findings/{id}/source-records` is unchanged and stays, because the view is built from it.
