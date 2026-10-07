### Changed: one list paging convention for scans, scan runs and scan workflows

- `GET /api/v1/scans`, `GET /api/v1/scans/{id}/runs`, `GET /api/v1/scan-runs` and `GET /api/v1/scan-workflows` read `page` (1-based) and `per_page` through one shared parser: a value that is not a positive whole number is answered 400 (it used to fall back to page 1 silently), and `per_page` is capped at 100.
- The four lists answer with one envelope, `{data, total, page, per_page, total_pages}`. `GET /api/v1/scans` no longer sends the duplicate `items` key, and `GET /api/v1/scan-runs` and `GET /api/v1/scan-workflows` send `data` instead of `items`.
- `GET /api/v1/scan-runs` takes `scan_id` (the runs of one scan, within the caller's tenant) and `status=blocked`; an unparsable `scan_workflow_id`, `scan_id` or `asset_id` is answered 400 instead of being ignored.
- Console: every Scans list keeps its state in plain URL parameters (`page`, `per_page`, `sort`, `q` and field-named filters); the prefixed `run_page`, `run_per_page`, `run_sort` and `run_status` are gone. A scan's run history pages locally and links to "View all runs" (`/scans/runs?scan_id=`).
- **Upgrade note:** API clients reading `items` from these four lists read `data`.
