### Added: a timeline for every run

- Each change of a sensor task (queued, claimed, started, refused, requeued,
  completed, failed, canceled, expired) is recorded with its attempt number,
  its sensor and the reason. A trigger on `commands` writes the record, so
  every writer is covered. Migration `001300` (`command_events`). Records are
  kept 30 days by the `command-event-retention` controller.
- `GET /api/v1/scan-runs/{id}/events` returns a run's timeline, oldest first,
  at most 2000 records. It needs `scans:read`, and a retest run also needs the
  finding to be readable. A platform scanning task never names its sensor, and
  its text is masked.
