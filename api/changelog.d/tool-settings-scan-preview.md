### Added: preview a scan's tool options on a sensor; scans and steps checked when saved

- `POST /api/v1/sensors/{id}/tool-settings/{tool}/preview` (`sensors:read`, read-only) resolves a scan's or a workflow step's options over the sensor's tool settings the way the sensor will: every option with its value and source (default, sensor or scan) and the config keys the sensor ignores; 422 by path when the sensor would refuse the options.
- Saving a single-scanner scan, and adding or editing a step pinned to a tool, checks its tool options against the organization's own sensors for that tool: a sensor-only option, a value out of bounds, or a raise of rate, concurrency or retries above what the sensor allows is refused when no sensor would accept it, instead of failing every job later.
