### Added: task budgets, per-command progress and stall detection

- Every scan command carries a layered budget (`budget`: per-target, task and
  stall seconds) from per-tool defaults. A sensor on sdk-go with task budgets
  bounds each target with it and stops a task only at twice its budget.
- Sensors report each held command's finished targets on the heartbeat
  (feature `command_progress`). A running task that finishes no target for
  its stall window, or runs past twice its budget, is re-queued like a lost
  lease (`commands_stalled_total`); a slow but progressing task is left alone.
- The run's task list returns `progress` (`done`, `total`,
  `last_progress_at`), `budget_seconds` and `stall_seconds`.
