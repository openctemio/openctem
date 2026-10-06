### Added: per-task logs from sensors, kept 14 days and shown on the run page

- Sensor protocol v2 gains `POST /api/v2/sensor/commands/{id}/logs` (feature `logs` on hello, RFC-029 §4.4.1): the sensor holding a command sends what its tool logged, in numbered batches through its outbox. A batch is stored once; a command keeps at most 200 batches and 2 MiB; the platform caps, cleans and redacts every line itself before storing it.
- Logs are kept 14 days (`command-log-retention` controller) and deleted with their command. Migration 001130 (`command_logs`, a new table).
- The run page's task table has a Logs action per task (`GET /api/v1/pipeline-runs/{id}/tasks/{task_id}/logs`, `pipelines:read`); lines are shown as plain text.
- Sensors send logs from sdk-go releases that support the `logs` feature; older sensors are unaffected.
