### Fixed: a sensor no longer gets back, at every policy flip, a task it refused under that policy

- A change of a sensor's reported local policy lifts its exclusion from the pending tasks it refused only when the sensor has not already refused the task under the new policy (the refusal records the policy digest). A policy report that flipped between two values handed the same task back to the same sensor each time.
- A task a sensor refused as a whole whose listed targets are all names that do not resolve (the sensor says `unresolvable`, or a sensor that predates the reason says `denied_by_policy` and the organization's own resolution state says the name is `not_resolving`) now completes with per-target skips instead of being re-queued to another sensor.

### Added: the run map counts the names active steps skipped because they no longer resolve

- A step that leaves out names known not to resolve records the count, and the run map shows "N names no longer resolve, skipped by active steps" (English and Vietnamese). Passive steps and the DNS resolution step still take those names.
