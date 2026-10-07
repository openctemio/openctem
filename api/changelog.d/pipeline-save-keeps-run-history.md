### Fixed: saving a pipeline no longer erases the history of its runs

- Saving a pipeline in the builder deleted and re-created every step. Step runs were deleted with their step, and the chaining inputs (`scan_step_outputs`) with their step run, so one save erased the step history of every past and running run of that pipeline.
- Steps are now updated in place and keep their ids (matched by the step `id` the builder sends, then by `step_key`). A removed step's step runs are kept: `step_runs.step_id` becomes NULL and the step run keeps its key, plus the step name and tool copied onto it when it was created (new columns `step_runs.step_name` and `step_runs.tool`, backfilled). Migration 001156.
- A change to a pipeline's steps is refused with `409 PIPELINE_RUN_ACTIVE` while a run of that pipeline is pending or running, so a running run is never changed under it. Every step write (full save, add, update, delete) is one tenant-scoped transaction.
- The step run response adds `step_name` and `tool`; `step_id` is omitted for a removed step.
