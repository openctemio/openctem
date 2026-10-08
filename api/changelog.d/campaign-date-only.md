### Fixed: remediation campaign dates accept a date alone and refuse anything else

- `start_date` and `due_date` on `POST` and `PATCH /api/v1/remediation/campaigns` take an RFC 3339 timestamp or a date (`YYYY-MM-DD`, UTC). A date alone is the start of that day for `start_date` and its last second (23:59:59 UTC) for `due_date`.
- A value in any other form is answered 400; before, create dropped it silently.
- `PATCH` with `"due_date": null` (or `start_date`) clears the date; before, null was ignored.
