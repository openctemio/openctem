### Added: a run's tasks count the targets the sensor's confinement could not reach

- A run task's `egress_refused_targets` counts the targets of a completed task that its sensor's network confinement kept the tool from reaching (ctis outcome `failed` with class `egress_refused`). The run page shows "could not reach N targets" for them instead of "produced nothing". The count comes from the sensor, is read only for completed tasks, and is never more than the task's own targets.
- ctis is updated so the platform accepts the `egress_refused` class: such a target is settled, not handed out again as unfinished.
