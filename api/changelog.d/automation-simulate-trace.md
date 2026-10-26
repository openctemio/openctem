### Added: automation simulate engine, run trace and delivery log

- A simulate run evaluates each action and notification step with a read-only evaluator that has no outbound client. It works out what the step would do (tags it would add, the status it would set, the ticket or message it would send) and changes nothing. A test proves that a fake outside server receives no request from a simulate run.
- Each run step records `in_count`, `out_count` and per-reason `skipped` counts. Each notification and ticket step records a delivery: what it sent in a live run, or would have sent in a simulate run, which is never sent. The payload keeps an allow-list of fields only, never a body, headers or a secret. `GET /api/v1/workflow-runs/{id}` returns them with `retained_until`, and `GET /api/v1/workflows/{id}/trace` sums them over a window.
- Simulate runs are kept 30 days and live runs 180 days. The new `automation-run-retention` controller deletes older ones. Migration 003351 (`automation_run_trace`) adds the columns and the `automation_deliveries` table.

### Security: automation runs follow the reader's data scope

- A run about a finding or asset outside the caller's data scope is no longer listed, and reading it answers 404. Trace counts include only runs the caller may see. Runs now always record the subject their trigger names.
