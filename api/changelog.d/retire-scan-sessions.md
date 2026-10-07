### Removed: scan sessions (`scan_sessions`, `/api/v1/scan-sessions`)

- The `scan_sessions` table and `GET /api/v1/scan-sessions`, `GET /api/v1/scan-sessions/stats`, `GET /api/v1/scan-sessions/{id}`, `DELETE /api/v1/scan-sessions/{id}` are removed (RFC-046 D2: Scan → Run → Task; CI runs are `ci_runs`). Nothing wrote the table since sensor protocol v1 was removed. Migration 001148 drops it; its down migration recreates it empty.
- CI coverage now counts a daemon scan of a repository from a completed sensor command whose report touched the repository, through the tool it named (it read the unwritten table). Tenant-scoped; another tenant's report naming the repository never counts.
- The Findings scan filter chip shows the producer id as given instead of looking it up in scan sessions (it always read "Unknown scan").
- **Upgrade note:** rows in `scan_sessions` are dropped; take them from the pre-upgrade backup if you need them. Clients of `/api/v1/scan-sessions` use scan runs (`GET /api/v1/scans/{id}/runs`, `/api/v1/pipeline-runs`).
