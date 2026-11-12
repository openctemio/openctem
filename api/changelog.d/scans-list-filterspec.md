### Added: the scans list and the runs list use the list query contract

- `GET /api/v1/scans` takes the same filter model as findings: `status`, `scan_type`, `schedule_type`, `sensor_preference`, `origin`, `tag`, `asset_group_id`, `scan_workflow_id`, `profile_id`, `scan_zone_id`, `scanner_name`, `last_run_status`, `created_by`, `name` (pattern or `name_contains`), the time fields `created_at`, `last_run_at` and `next_run_at` (`_gte`, `_lte`, `_gt`, `_lt`), `total_runs` and `failed_runs`, each with a comma list, `_not` lists and ranges where the type allows.
- `POST /api/v1/scans/search` takes a filter document (OR, nesting, long id lists) with the same fields, permission (`scans:read`) and visibility rules as the list.
- `GET /api/v1/scan-runs` takes `trigger_type`, `asset_id`, `id`, `created_at`, `started_at`, `completed_at`, `duration` (seconds) and `total_findings` filters besides the ones it had, as lists and ranges.
- The query language has a `scans` entity (`POST /api/v1/query/parse`, `GET /api/v1/query/schema`, `POST /api/v1/query/run`), and the scans page has the query text box with an Advanced chip for a filter its controls cannot show.

### Deprecated: the scans list parameters `search` and `tags`

- `search` is now `q` and `tags` is now `tag` on `GET /api/v1/scans`. The old names keep working with `Deprecation`, `Sunset` (2027-05-08) and `Warning` headers, and are counted in `deprecated_query_param_requests_total`.

### Behaviour change: the scans list and the runs list refuse unknown parameters

- An unknown query parameter on `GET /api/v1/scans` or `GET /api/v1/scan-runs` is now `400 INVALID_FILTER` instead of being ignored. A value that is not valid for its field (a status that does not exist, a malformed id) is the same error and never quotes the value.
- `GET /api/v1/scans?asset_group_id=` now also matches a scan that names the group in its list of groups, not only its first group.
