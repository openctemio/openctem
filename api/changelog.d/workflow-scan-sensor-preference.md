### Security: workflow scans reach platform sensors only under the same checks as single scans

- The steps of a workflow scan used to follow the workflow's own sensor
  preference. When that preference was `platform`, the steps of a scan of an
  asset group or of internal targets could be queued for shared platform
  sensors. A scan set to `platform` was also never checked.
- A workflow scan now follows the scan's `sensor_preference`, decided when it
  is triggered:
  - `platform` is refused (400 `PLATFORM_SENSOR_REFUSED`) for asset groups,
    internal targets, unproven targets and tenants without platform access,
    as it is for single scans;
  - `auto` may use platform sensors only when none of these applies, and then
    only for steps whose tool no tenant sensor has;
  - `tenant` and "run on tenant sensors only" keep every step on the tenant's
    sensors.
- The decision is kept in the run (`sensor_routing`). A routing value sent in
  the trigger context is ignored.
