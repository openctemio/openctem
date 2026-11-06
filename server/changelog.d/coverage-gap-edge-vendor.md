### Fixed: a host an edge protection blocked no longer reads as covered

- A completed task from a sensor that sends no per-target outcomes covered every host, even one its coverage gaps listed as blocked. The coverage ledger now reads `coverage_gaps` too: a blocked host settles as edge blocked (or challenged), a rate-limited one as rate limited, a stopped one as unreachable and a proxy failure as a platform-side fault. A gap beats a done outcome for the same host, and a gap list shorter than its count covers nothing of the task.

### Added: the edge protection vendor on coverage gaps and the asset coverage view

- Run task coverage gaps carry `edge` (challenged or blocked) and `vendor` (a short token the sensor sends, shown as text); the asset coverage entry carries `last_edge_vendor`. The run page and the asset coverage section say "blocked by edge protection (vendor)" and link to the fixes: allow the scanner addresses, use another proxy pool, lower the scan rate.
- Migration 20261031134406 adds the nullable `asset_coverage.last_edge_vendor` column (catalog-only, no rewrite).
