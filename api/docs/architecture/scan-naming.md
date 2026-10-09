# Scans, scan workflows, runs and CI: one name per concept

"Pipeline" is a CI word. In OpenCTEM it names only a customer's CI pipeline.
The scan side uses the names below at every layer: the console, the API, the
database, the Go packages and these docs. A bare "workflow" or "pipeline" is
never used on its own.

| Concept | Console | API | Database | Go package |
|---|---|---|---|---|
| The graph of steps a Scan runs | Scan workflow ("Workflows" inside Scans) | `/api/v1/scan-workflows` | `scan_workflows`, `scan_workflow_steps` | `pkg/domain/scanworkflow` |
| A scan configuration (targets, what to run, schedule) | Scan | `/api/v1/scans` | `scans` (`scans.scan_workflow_id`) | `pkg/domain/scan`, `internal/app/scan` |
| One execution of a Scan | Scan run | `/api/v1/scan-runs` | `scan_runs` | `pkg/domain/scanrun`, `internal/app/scanrun` |
| One step of a scan run | Step | in `GET /api/v1/scan-runs/{id}` | `scan_run_steps` | `scanrun.StepRun` |
| One unit of sensor work of a step (a chunk of targets) | Task | `/api/v1/scan-runs/{id}/tasks` | `commands` (`commands.scan_run_step_id`, payload `scan_run_id`) | `pkg/domain/command` |
| An event rule (when / if / then) | Automation | `/api/v1/workflows` (renamed to `/api/v1/automations` with the automations redesign) | `automations`, `automation_runs`, `automation_run_steps` (migration 001528) | `pkg/domain/automation`, `internal/app/automation` |
| A customer's CI pipeline (repository + config file) | CI pipeline | `/api/v1/ci/pipelines` | `ci_pipelines` | `pkg/domain/cirun` |
| One CI pipeline execution reporting to OpenCTEM | CI run | `/api/v1/ci/runs` | `ci_runs` | `pkg/domain/cirun` |

A vendor's own word appears only as provenance, for example "GitHub workflow
`.github/workflows/deploy.yml`" or "GitLab pipeline #123".

## Permissions and modules

- Scan workflows: `scans:workflows:read`, `scans:workflows:write`,
  `scans:workflows:delete`, module `scan_workflows`.
- Scan runs belong to the Scans area: reading needs `scans:read`, cancelling
  needs `scans:write`, module `scans`.
- A scan run starts only by triggering a Scan (`POST /api/v1/scans/{id}/trigger`
  or its schedule), so every run passes the same gate: scope, freeze windows,
  sensors and tools. There is no direct "run this workflow" endpoint.

## History

Migration 001285 renamed `pipeline_templates`, `pipeline_steps`,
`pipeline_runs` and `step_runs` (and their columns, indexes, constraints, RLS
policies and trigger) in place, rewrote queued command payload keys, and
mapped `integrations:pipelines:{read,write,delete}` one to one to
`scans:workflows:*`. Migration 001286 removed `integrations:pipelines:execute`,
which gated only the removed direct run. Audit entries written before the
rename keep their `pipeline_template.*` and `pipeline_run.*` actions.
