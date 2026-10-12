### Behaviour change: scan workflows and scan runs are named the same at every layer

- "Pipeline" now means a CI pipeline only. The graph of steps a Scan runs is a **scan workflow**, and one execution of a Scan is a **scan run** with **steps** (and sensor **tasks**).
- API: `/api/v1/pipelines` is now `/api/v1/scan-workflows` and `/api/v1/pipeline-runs` is now `/api/v1/scan-runs` (tasks, task logs, stages, cancel). The old paths return 404; there are no aliases.
- JSON: `pipeline_id` is `scan_workflow_id` (scans, scan runs, previews, run filters), `pipeline_run_id` is `scan_run_id`, `step_run_id` is `scan_run_step_id`, the scan list's `pipeline_name` is `scan_workflow_name` and the scan stats `pipelines` counts are `scan_runs`. The `scan_completed` automation event carries `scan.scan_workflow_id`.
- Permissions: `integrations:pipelines:{read,write,delete}` are `scans:workflows:{read,write,delete}`, mapped one to one in system and custom roles, API key scopes and licenses (migration 001285). Reading and cancelling scan runs needs `scans:read` / `scans:write`, like the rest of the Scans area. The module `scan_pipelines` is `scan_workflows`.
- Audit: new entries use `scan_workflow.*`, `scan_workflow_step.*` and `scan_run.*`; entries written before the upgrade keep their `pipeline_*` actions (the audit chain is never rewritten).
- Database (migration 001285): `pipeline_templates` → `scan_workflows`, `pipeline_steps` → `scan_workflow_steps`, `pipeline_runs` → `scan_runs`, `step_runs` → `scan_run_steps`, with their columns, indexes, constraints, RLS policies and trigger, renamed in place. Queued commands keep reporting to their run: their payload keys are rewritten in the same migration.
- **Upgrade note:** run the migrations before the new API starts. Scripts or API keys that call `/api/v1/pipelines` or `/api/v1/pipeline-runs` must switch to the new paths and field names.

### Removed: starting a scan workflow run outside a Scan

- `POST /api/v1/pipelines/{id}/runs` (the "Run now" button on the workflow list) is removed with its `integrations:pipelines:execute` permission (migration 001286, archived in `access_control_removed_archive`). A scan run starts only by triggering a Scan, so every run passes the scan gate (scope, freeze windows, sensors, tools) and appears in the scan's history. `GET /api/v1/pipelines/{id}/runs` is removed too: list a workflow's runs with `GET /api/v1/scan-runs?scan_workflow_id=`.
