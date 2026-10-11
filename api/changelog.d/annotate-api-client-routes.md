### Added: the OpenAPI spec documents the automation routes kept for API clients

- The spec now describes `POST /api/v1/assets/import/csv`, `POST /api/v1/assets/{id}/relationships/batch`, `GET /api/v1/compliance/controls/{id}`, `GET /api/v1/ctem-ids`, `POST /api/v1/threat-intel/enrich` and `GET /api/v1/vulnerabilities/cve/{cveId}/affected-assets`. These routes have no screen in the web app and are kept for automation (issue #970); they leave the undocumented-routes baseline.
