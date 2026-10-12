### Added: every run says who or what started it

- Runs in `GET /api/v1/scan-runs`, `GET /api/v1/scan-runs/{id}` and the scan
  run reads now include `trigger`: `{type, id, run_id, label}`. `type` is
  `user`, `schedule`, `automation`, `api`, `webhook`, `asset_discovery` or
  `system`. It names the person (with a display name), the automation and the
  automation run behind the run, or the scan for a scheduled run.
- Before this, a run an automation started read "manual", and the Runs list
  showed the raw trigger type. The "Triggered by" column now reads the person's
  name, "Automation", "Schedule" or "Platform".
