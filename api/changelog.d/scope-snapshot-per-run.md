### Added: a hashed scope snapshot for every scan run

- When a scan run starts, the authority its targets relied on (the covering entries with their authorization source, program and tier; those programs with their accepted terms hash and program exclusions; the count of uncovered targets) is stored canonically with its SHA-256, one body per distinct hash (migration 001495 tables). `GET /api/v1/scan-runs/{id}/scope-snapshot` returns it to callers who may see the run and hold `scope:read` or `programs:read`. RFC-065.
