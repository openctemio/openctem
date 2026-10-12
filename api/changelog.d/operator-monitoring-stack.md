### Added: operator monitoring stack with Telegram and Slack alerts

- `deploy/observability/`: a compose profile (`observability`) with Prometheus, Alertmanager,
  node-exporter, cAdvisor, the Postgres and Redis exporters and synthetic probes, plus optional Grafana
  (`grafana` profile) with an overview dashboard. It joins the stack's network and publishes nothing on a
  public interface.
- About 50 alert rules (API and web availability, 5xx rate, latency, panics, error log bursts, schema
  behind/dirty, sensors offline or impaired, stuck command queue and scan runs, ingest and outbox lag,
  automation auto-pauses, audit chain breaks, login failure spikes, rate-limit spikes, Postgres, Redis,
  disk, memory, OOM kills, container restarts, TLS expiry, backups), each with a runbook in
  `docs/operations/monitoring.md`, routed to Telegram and/or Slack with grouping, inhibition and resolved
  messages.
- The Postgres exporter connects as a `pg_monitor`-only role (`deploy/observability/postgres/monitor-role.sql`).
- **Upgrade note:** to use it, set `METRICS_TOKEN` on the API, create the monitor role and follow
  "Install (Docker Compose)" in `docs/operations/monitoring.md`. Nothing changes for installs that do not.
