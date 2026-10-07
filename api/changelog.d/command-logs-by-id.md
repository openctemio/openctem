### Added: any command's logs can be read

- `GET /api/v1/commands/{id}/logs` returns the log lines a sensor sent for any command (scan, retest, validate, connector, system), not only for the tasks of a scan run. It returns at most 5,000 lines, oldest first, kept 14 days.
- It is gated by `commands:read`, like the command itself.
- A command about a finding (a retest's commands, a validate job) also needs `findings:read` and the finding in the caller's data scope; otherwise it is not found.
- Another organization's command is not found.
