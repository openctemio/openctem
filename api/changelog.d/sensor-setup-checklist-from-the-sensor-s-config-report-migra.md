### Added: sensor setup checklist from the sensor's config report (migration 001054)

- Sensors that see the hello feature `config_report` send the results of
  their preflight checks with `PUT /api/v2/sensor/config-report` (at most
  64 KiB) and echo its digest on every heartbeat (`config_report`); a
  different digest gets the heartbeat action `send_config_report`.
- The platform sanitizes every report (closed sets, typed and re-validated
  parameters, bounded plain text, unknown members dropped and listed), keeps
  the latest per sensor, and never stores a setting value even if a sensor
  sends one.
- `GET /api/v1/sensors/{id}/config-report` (`sensors:read`) explains each
  check from the platform's own catalog, with fix snippets for env, Docker
  Compose and Helm; older sensors get a checklist derived from the heartbeat.
- New health reasons `config_check_failed`, `config_check_warning` and
  `config_report_stale`; the sensor list and detail carry `config_health`.
