### Changed: a workflow scan over several scan zones runs one zone run per zone
- A workflow scan whose targets fall in several scan zones (or in a zone and outside every zone) is no longer refused with `ZONE_SPLIT_REQUIRED`. It runs as one zone run per zone under a parent run; each zone run uses only its zone's sensors, the targets outside every zone route to shared or organization sensors as before, and the parent settles from its zone runs.
- The run detail shows a "Scan zones" section with each zone's targets, status and zone run. The routing preview reports `zone_runs` instead of an error.
- Migration: nullable `scan_runs.parent_run_id` (same-tenant foreign key) and a partial index.
