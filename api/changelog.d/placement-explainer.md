### Added: a queued scan task says why it waits

- `GET /api/v1/scan-runs/{id}/tasks/{task_id}/placement` (`scans:read`) explains a queued task: what holds it whatever the sensor (scan window, busy host, expired), how many of the organization's sensors may take it and how many of those are busy, and each reason that keeps it from the others (zone, tool, capability, grant, intensity, local policy, private targets, opt-ins, refusals). Callers who also have `sensors:read` get each sensor's verdict; platform scanning is never broken down into sensors.
- The explanation reads the claim's own SQL predicates and dispatch gate, and a database test keeps it in agreement with the poll. Details in `docs/architecture/placement.md`.
