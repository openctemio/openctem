### Fixed: the deadline admission log reports whole seconds

- The "step not started: the run's deadline is too close" log line reports
  `left_seconds` and `need_seconds` as integers (code scanning flagged the
  durations as log input derived from user settings).
