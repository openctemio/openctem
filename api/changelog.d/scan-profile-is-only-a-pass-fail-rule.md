### Removed: a scan profile is only the pass/fail rule

- A scan profile's tools, intensity, timeout and max concurrent scans were stored but never applied when a scan was dispatched, so choosing "low intensity" limited nothing. The profile is now only the quality gate (pass/fail rule).
- `POST` and `PUT /api/v1/scan-profiles` answer `400` when the body sets `tools_config`, `intensity`, `max_concurrent_scans` or `timeout_seconds`. Responses no longer carry them. The console drops those fields and the New scan step is renamed "Pass/fail rule (optional)".
- **Upgrade note:** API clients that still send those fields must stop. No migration: the columns stay with their defaults and are dropped in a later release.
