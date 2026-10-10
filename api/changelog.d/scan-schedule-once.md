### Fixed: a scan scheduled to run once, later, now runs

- New Scan, Schedule for later, Once: the scan used to be saved as a manual scan that never ran, while the confirmation said it was scheduled. You now pick the date, time and timezone of the run, and the scan runs once then. The API takes `schedule_type: once` with `run_at` (a minute to a year ahead) and returns `schedule_run_at`. Migration 001670 adds `scans.schedule_run_at`.
- Scheduled times are in the timezone you pick, your own by default. The wizard did not send a timezone, so every time was read as UTC.
- Monthly schedules run on the day of the month you pick (it was always the 1st). A shorter month runs on its last day.
- Cloning a scan keeps its recurrence rule (an rrule clone had none and never ran).
- **Upgrade note:** run migrations (001670).
