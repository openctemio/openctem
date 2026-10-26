### Added: alerts for a drifting host clock and for exporters that cannot connect

- Monitoring alerts `HostClockUnsynchronised` and `HostClockOffsetLarge` (sensor request signatures allow only 2 minutes of skew), and `PostgresExporterCannotConnect` and `RedisExporterCannotConnect` (an exporter that is up but cannot log in), with promtool tests and runbooks.
- The observability stack applies `postgres/monitor-role.sql` on every `up` through the `postgres-monitor-role` one-shot service, so the exporter's database role can no longer be missing.
