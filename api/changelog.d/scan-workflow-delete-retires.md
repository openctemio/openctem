### Fixed: deleting a scan workflow keeps its run history

- `DELETE /api/v1/scan-workflows/{id}` used to delete every run of the
  workflow, along with their steps, outputs and stage plans (ON DELETE CASCADE).
  A workflow that has runs is now **retired** instead. It leaves the workflow
  lists, and it can still be read by id with `retired_at`, so its runs keep
  their graph. It cannot be edited or run (409 `WORKFLOW_RETIRED`, also for a
  scan that uses it), and its name can be used again. A workflow without runs
  is still deleted.
- A delete while a run is pending or running is refused (409
  `PIPELINE_RUN_ACTIVE`).
- `scan_runs.scan_workflow_id` no longer cascades, so no delete can remove a
  run again. Migration `001296`.
