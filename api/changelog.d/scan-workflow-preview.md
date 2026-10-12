### Added: preview of a workflow scan before it starts

- `POST /api/v1/scans/workflow-preview` (`scans:write`) shows what a workflow scan would do, before it is saved or started. It creates nothing:
  - per step: the capability and tier, the tool the planner picks, and its sensor status (ready, sensors offline, no sensor);
  - the targets: zone routing and scope exclusions, with at most 20 samples;
  - a freeze window active now.
- It uses the trigger's code. A step the trigger would refuse (`NO_SENSOR_FOR_TOOL`) carries the same code and message, and `blocking` is true when a trigger with these settings would be refused (a test checks this parity).
- The new-scan wizard shows the preview for a workflow scan on its last step.
- A workflow that is neither the organization's own nor a system workflow is not found.
