### Changed: the scan wizard expands coverage with one inventory request

- `GET /assets` takes `under` (comma-separated DNS names, at most 10): the names equal to or below them, with the caller's data scope. The new-scan coverage expansion asks once for every typed domain instead of one search per domain.
