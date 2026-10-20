### Changed: scan jobs no longer carry the scan's routing tags or own-sensors flag
- `routing_tags` and `tenant_runner_only` were sent in every scan job payload but read by no sensor, and the tag names reached shared sensors too. They are removed from the payload and from the context a sensor receives; the platform still uses `tenant_runner_only` from the run context to choose where a step runs.
