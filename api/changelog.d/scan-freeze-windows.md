### Added: scan freeze windows

- Organization-wide or per-zone windows (one-off, or weekly in an IANA time zone) in which no active (T1/T2) scan work is dispatched: `/api/v1/scan-freeze-windows` (read with `scans:read`, manage with `sensors:zones:write` / `sensors:zones:delete`). Passive work and ingest continue.
- Enforced at claim time for every command path (trigger, pipeline steps, direct commands, validation, coverage and EASM dispatch); scheduled runs are deferred to the window's end; other triggers answer `409 SCAN_FREEZE_ACTIVE` unless the caller sends `override_freeze` and holds the new permission `scans:freeze:override` (owner and admin; audited).
- Migration `001115` (new table, two `freeze_override` columns with a default, one permission). See `docs/architecture/scan-zones.md#freeze-windows`.
