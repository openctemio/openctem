### Added: see how a workflow step is shared between sensors

- `GET /pipeline-runs/{id}/stages` now gives each stage its chunk counts (total, queued, running, completed, failed) and the sensors that took them. A platform job is listed as platform, without naming the platform sensor.
- In the scan run panel, each stage lane shows "2 of 10 chunks done, 3 running, …" and the share per sensor. The workflow graph shows the chunks done and how many sensors work on each step.
- The workflow preview in the new-scan dialog shows each step's chunk size and how many sensors can work on it at once.
