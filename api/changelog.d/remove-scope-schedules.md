### Removed: the scope schedules API

- `/api/v1/scope/schedules` (list, get, create, update, enable, disable,
  run, bulk delete, delete) is removed, and `GET /api/v1/scope/stats` no
  longer returns `total_schedules` / `enabled_schedules`. Scope schedules
  never ran a scan, and the web had already dropped the tab; schedule scans
  in the Scans area. Migration 001067 drops the empty `scan_schedules`
  table; the down migration recreates it.
- **Upgrade note:** an API client that created scope schedules gets 404;
  create a scheduled scan instead.
