### Fixed: task logs keep every attempt of a command

- A command released (sensor restart, lease expiry) and claimed again lost
  the logs of its new attempt: the sensor numbers each attempt's batches
  from 0 again and the platform took them for replays of the first
  attempt, answering 200 without storing them. Batches are now keyed by the
  command's lease epoch, which the platform reads from the command (the
  sensor never sets it), so every attempt's lines are kept (migration
  `command_logs_per_attempt`; existing batches get their command's current
  epoch).
- A batch with the seq of a stored one but other lines in the same attempt
  answers `dropped` instead of `stored`, is logged and is counted in
  `openctem_command_log_batches_dropped_total`; batches over the per-command
  caps are counted there too.
- A log batch that states a lease epoch (`X-OpenCTEM-Lease-Epoch`) the
  command is no longer held under is refused with 409, never filed under the
  new attempt.
- The task logs dialog reads lines oldest attempt first and marks where each
  attempt starts when there was more than one.
