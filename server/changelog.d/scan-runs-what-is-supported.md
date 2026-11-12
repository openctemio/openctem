### Behaviour change: a scan runs as far as the organization's tools and sensors support

- Creating or saving a scan, and saving or activating a workflow, is no longer refused because a step's
  tool is not installed, is turned off, has no sensor, or because no tool implements a step's capability
  (`WORKFLOW_NOT_RUNNABLE` is removed; a single scan on a disabled scanner can be saved too). A definition
  that is wrong in itself is still refused.
- At run time (manual and scheduled alike) such a step is skipped with its reason and a code
  (`NO_MATCHING_TOOL`, `TOOL_NOT_INSTALLED`, `TOOL_DISABLED`, `NO_SENSOR_FOR_TOOL`), required or optional;
  the steps that need its results are skipped as `DEPENDENCY_SKIPPED`; the run goes on with every other
  step and ends `partial`, not `completed` or `failed`. Before, one step without a tool or sensor refused
  the whole run (`NO_SENSOR_FOR_TOOL`, `TOOL_NOT_FOUND`, `TOOL_DISABLED`) or failed it.
- Only a trigger in which no step can run is refused, as a blocked run with `NO_RUNNABLE_STEPS` naming the
  missing steps and why.
- Scope, intensity, approvals and the passive-only entitlement still refuse a run as before.
- The run API lists each step's `skip_reason` (step runs and run map nodes); the run view shows it and
  explains the new codes in English and Vietnamese.
