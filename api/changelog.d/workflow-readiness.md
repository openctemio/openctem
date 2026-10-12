### Added: workflow readiness, and a scan refuses a workflow that cannot run

- `GET /api/v1/scan-workflows?include=readiness` (and `GET /{id}?include=readiness`)
  says, for each workflow, whether it can run for the caller's organization
  now and why, per step:
  - `ready`: a tool that runs the step is on an online sensor allowed to run it;
  - `waiting`: such sensors exist but none is online;
  - `ci_only`: code analysis that runs in the CI images;
  - `blocked`: no enabled tool runs the step, or no sensor offers one.
  Each step carries a reason and a fix ("Add a sensor with naabu", "Enable
  httpx", "Set up the CI pipeline integration").
- Readiness is computed in one pass from the sources the dispatch gate reads
  (the tool catalog, the organization's sensors, grants, manifests and zones)
  and the platform scanning offer. Platform sensors appear only as platform
  scanning, never per sensor. The inputs are cached for 10 seconds per
  organization.
- Creating a scan with a blocked or CI-only workflow, or starting one, is
  refused with 400 `WORKFLOW_NOT_RUNNABLE`, naming the steps and why. A
  waiting workflow can be scheduled; a run now still needs an online sensor
  (`NO_SENSOR_FOR_TOOL`). Readiness is checked again when a run starts.
