### Added: operator metrics for alerting on the running platform

- `/metrics` (token-gated by `METRICS_TOKEN`, never routed by the gateway) now also reports:
  `openctem_panics_recovered_total{where}`, `openctem_log_records_total{level,component}` (WARN/ERROR,
  counted before sampling), `openctem_auth_login_failures_total{reason}`,
  `openctem_automation_runs_total{status}`, `openctem_automations_auto_paused_total`,
  platform-wide gauges (`openctem_sensors{kind,health}`, `openctem_sensors_config_health`,
  `openctem_sensors_sdk`, `openctem_commands{state}`, `openctem_command_oldest_pending_seconds`,
  `openctem_scan_runs_open`, `openctem_scan_runs_past_deadline`, `openctem_outbox_entries{status}`,
  `openctem_outbox_oldest_pending_seconds`, `openctem_schema_version{source}`, `openctem_schema_dirty`,
  `openctem_build_info`, `openctem_ops_collector_up`) and the connection pool (`go_sql_*`).
- The platform-wide gauges are read with a few aggregate queries at most every 30 seconds, whatever the
  scrape rate. Labels carry no tenant, user, sensor or run identity.

### Fixed: panicking requests, rate-limited requests and URL paths in the HTTP metrics

- A request that panicked was never counted in `http_requests_total` and left `http_requests_in_flight`
  one higher for good; it is now counted as the 500 it returns. Requests refused by the global rate
  limit (429), the concurrency limit and the body limit are now counted too.
- **Behaviour change:** the `path` label of `http_requests_total`, `http_request_duration_seconds` and
  `http_response_size_bytes` is the matched route pattern (`/api/v1/assets/{id}`), or `unmatched` when no
  route matched. It was the raw path with ids replaced, which carried names and hosts from the URL into
  the label and let any caller create a new series per random path. Dashboards that matched raw paths
  must use the route pattern.
