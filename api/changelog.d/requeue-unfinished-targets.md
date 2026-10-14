### Changed: a task that ends with unfinished targets runs only those again

- When a sensor completes a scan task with per-target outcomes (`target_outcomes`: done, failed, skipped, unfinished) and some targets are unfinished, the finished targets are settled and a new task carrying only the unfinished targets is queued in the same transaction (`commands.retry_of` names the task it continues; migration `002098_command_retry_of`). The step settles with its last task, so it waits for the follow-up and counts its results. A finished target is never run twice because a later one stopped the task.
- Dispatch attempts count per chunk of targets: a run that settled targets leaves the remaining chunk's attempts as they were; a run that settled none adds one. One host that never answers exhausts only its own task, not the targets already done.
- Single-scanner scan tasks now carry their step id (`commands.scan_run_step_id`), as workflow and zone-routed tasks already did.
- Sensors without per-target outcomes are unaffected.
