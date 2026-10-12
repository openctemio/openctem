### Changed: a run executes the workflow version it started with

- When a scan workflow run starts, the workflow's settings and steps are saved
  as an immutable version (only when they changed since the last one), and the
  run reads that version until it ends. Editing a workflow while it runs now
  changes the next run, never the running one; before, the running one picked
  up the edited steps and settings halfway through.
- `GET /scan-runs` and `GET /scan-runs/{id}` return `scan_workflow_version`
  and `spec_digest`.
- Migration 001321 adds `scan_workflow_versions` and the two run columns.
  Runs started before the upgrade keep reading the live workflow.
