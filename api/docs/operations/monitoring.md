# Monitoring and alerting (operators)

How the operator of an OpenCTEM installation learns that the running platform
is broken (API down, errors, full disk, stuck queues, failing backups) through
Telegram and/or Slack, with a runbook for every alert.

This is about the platform itself. What a tenant is told about its own data
(new findings, SLA breaches) is the notification system
([architecture/notification-system.md](../architecture/notification-system.md)).

## How it fits together

```
  OpenCTEM stack (compose network)                monitoring stack (deploy/observability)
  ┌───────────────────────────────┐   scrape      ┌───────────────────────────────┐
  │ api  /metrics (bearer token)  │◄──────────────│ prometheus  rules, 15d, 2GB   │
  │ ui   /login                   │◄── probe ─────│ blackbox    /health, /login,  │
  │ gateway  https://…/login      │◄── probe ─────│             public URL + TLS  │
  │ postgres ◄── postgres-exporter (pg_monitor)   │ node-exporter  host           │
  │ redis    ◄── redis-exporter                   │ cadvisor       containers     │
  └───────────────────────────────┘               │ alertmanager ──► Telegram     │
                                                  │                ──► Slack      │
                                                  │ grafana (optional)            │
                                                  └───────────────────────────────┘
```

- **The API** serves Prometheus metrics at `GET /metrics` on its own port. It
  answers 404 unless the request carries `Authorization: Bearer
  <METRICS_TOKEN>` (constant-time compare), and the gateway refuses `/metrics`
  for everyone, so the endpoint is reachable only from inside the deployment.
- **Errors in logs** are counted by the API itself
  (`openctem_log_records_total{level,component}`, WARN and ERROR, before
  sampling) and panics by `openctem_panics_recovered_total{where}`. There is no
  log pipeline: the alert says which component, the container log has the
  detail (`docker logs <api container> | grep level=ERROR`).
- **Exporters** cover what the API cannot see: the host (disk, memory, OOM
  kills), containers (restarts, OOM, memory limits), Postgres, Redis, and
  synthetic probes of the health check, the sign-in page and the public URL
  (including its TLS certificate).
- **Alertmanager** groups, deduplicates and routes alerts to Telegram and
  Slack, sends a message when an alert resolves, and holds silences.

## Install (Docker Compose)

Everything is in `deploy/observability/`. It joins the network of the running
OpenCTEM compose stack and publishes nothing on a public interface.

1. Set the API's metrics token. In the stack's `.env` and on the `api`
   service: `METRICS_TOKEN=<openssl rand -hex 32>`. Restart the API.
2. Create the exporter's database role (least privilege: `pg_monitor`, no
   table access, at most 3 connections):

   ```bash
   docker compose exec -T postgres psql -U openctem -d openctem \
     -v pw="$OBS_PG_MONITOR_PASSWORD" -f - < deploy/observability/postgres/monitor-role.sql
   ```

3. Put the settings in the same `.env` (secrets only there, never in the
   repository):

   | Variable | Meaning |
   |---|---|
   | `METRICS_TOKEN` | Same value as the API's. Required. |
   | `ALERT_TELEGRAM_BOT_TOKEN`, `ALERT_TELEGRAM_CHAT_ID` | Telegram receiver: a bot from @BotFather, added to the group; the chat id is a number (negative for a group). |
   | `ALERT_SLACK_WEBHOOK_URL` | Slack receiver: an incoming webhook of the alert channel. |
   | `OBS_PG_MONITOR_PASSWORD` | Password of `openctem_monitor`. |
   | `REDIS_PASSWORD` | The stack's Redis password (already there). |
   | `OBS_PUBLIC_URL` | The URL users open, e.g. `https://openctem.example.com`. |
   | `OBS_PUBLIC_PROBE_MODULE` | `http_2xx` for a public CA; `http_2xx_internal_ca` when the gateway uses its internal CA. |
   | `OBS_APP_NETWORK` | The stack's docker network (default `openctemio_openctem-network`). |
   | `OBS_API_UPSTREAM`, `OBS_WEB_UPSTREAM` | Defaults `api:8080`, `ui:3000`. |
   | `OBS_TEXTFILE_DIR` | Host directory of `*.prom` status files (backups), default `/var/lib/node_exporter/textfile`. |
   | `OBS_CONTAINER_REGEX` | Containers watched for restarts/OOM, default `openctemio-.*\|openctem-sensor.*`. |
   | `OBS_RETENTION_TIME`, `OBS_RETENTION_SIZE` | Defaults `15d`, `2GB`. |
   | `OBS_GRAFANA_ADMIN_PASSWORD` | Required only with the `grafana` profile. |

   Either receiver may be left out; with neither, alerts are only visible in
   the Alertmanager UI.

4. Start it:

   ```bash
   docker compose -p openctemio-obs --env-file .env \
     -f deploy/observability/docker-compose.yml --profile observability up -d
   # dashboards too: add --profile grafana
   ```

5. Report backups (see [BackupStale](#backupstale)) and
   [test the alert path](#test-the-alert-path).

UIs, bound to 127.0.0.1 on the host (use an SSH tunnel, e.g.
`ssh -L 9093:127.0.0.1:9093 host`): Prometheus `:9091`, Alertmanager `:9093`,
Grafana `:3001` (dashboard "OpenCTEM operations").

Memory: the containers are capped at 512M (Prometheus), 192M (cAdvisor), 64M
each (Alertmanager, node-exporter, postgres-exporter), 32M each
(redis-exporter, blackbox): under 1 GiB of limits, about 150 MiB in use on a
small install (Prometheus grows with retention, within its 2 GB disk cap).
Grafana adds up to 384M (about 200 MiB in use).

Validate a change to the configuration with
`deploy/observability/test/check-config.sh` (promtool, rule unit tests,
amtool), which CI also runs.

Kubernetes: the Helm chart has the same alert rules and a ServiceMonitor for
the API (`monitoring.*` values of the `openctemio/helm-charts` chart).

## Security

- No monitoring UI or exporter is published on a public interface or routed
  by the gateway. The UIs bind to 127.0.0.1 and have no login of their own
  (Grafana has one); anyone with a shell on the host can read them.
- The metrics token, the Telegram bot token and the Slack webhook URL come
  from the environment and are written at start to 0400 files on a tmpfs
  inside the container; they are never in the rendered configuration, the
  repository or the alert text.
- The Postgres exporter connects as `openctem_monitor` (`pg_monitor` only).
- node-exporter mounts the host root read-only and cAdvisor reads the docker
  socket: both are root-equivalent on the host. They are on the internal
  network only, with read-only filesystems and `no-new-privileges`.
- **What an alert contains.** Metric labels are infrastructure vocabulary
  only: job, instance, component, controller, probe, reason, container name.
  No metric carries a tenant, user, sensor or run id, an email, or a target
  host (the API's label tests enforce this, and HTTP metrics label the route
  pattern, never the URL path). Alert text is counts, ratios and durations.
  Telegram and Slack are outside the platform, so this is a rule for anyone
  adding a metric or an alert.

## Metrics the API exposes

Besides the Go runtime and process metrics:

| Metric | Labels | What |
|---|---|---|
| `http_requests_total`, `http_request_duration_seconds`, `http_response_size_bytes` | method, path (route pattern or `unmatched`), status | Every answer, including panics (500), rate-limit refusals (429) and limit refusals. |
| `openctem_panics_recovered_total` | where (`http` or the background task) | Panics caught by a recover(). |
| `openctem_log_records_total` | level (warn, error), component | Log records written, before sampling. |
| `openctem_auth_login_failures_total` | reason (invalid_credentials, locked, suspended, other) | Refused password sign-ins. |
| `openctem_automation_runs_total`, `openctem_automations_auto_paused_total` | status | Finished automation runs; automations paused after repeated failures. |
| `openctem_web_client_errors_total` | kind | Errors reported by browsers (when the web reporter is enabled). |
| `openctem_sensors`, `openctem_sensors_config_health`, `openctem_sensors_sdk` | kind (platform, tenant), health / config_health / status | Active sensors, platform-wide counts. |
| `openctem_sensors_unhardened` | kind (policy_none, pin_none, network_unenforced, bearer_key) | Active tenant sensors by unhardened reason (a sensor with several reasons counts under each). |
| `openctem_commands`, `openctem_command_oldest_pending_seconds` | state | Sensor command queue. |
| `openctem_scan_runs_open`, `openctem_scan_runs_past_deadline` | | Open scan runs and those the reaper should have ended. |
| `openctem_outbox_entries`, `openctem_outbox_oldest_pending_seconds` | status | Notification outbox. |
| `openctem_schema_version`, `openctem_schema_dirty` | source (applied, shipped) | Database migration state. |
| `openctem_build_info` | version, commit | Running build. |
| `openctem_ops_collector_up` | | 1 when the platform-wide counts above were read. They are read with a few aggregate queries at most every 30 s, whatever the scrape rate. |
| `go_sql_*` | db_name | API connection pool. |
| `ingest_queue_depth`, `ingest_jobs_processed_total`, `ingest_v2_requests_total` | outcome … | Result ingestion. |
| `openctem_controller_reconcile_errors_total`, `openctem_controller_last_reconcile_timestamp_seconds` | controller | Background controllers. |
| `openctem_security_audit_chain_breaks_total` | reason | New breaks of the audit log hash chain. |
| `openctem_redis_*` | | Redis client and rate limiters. |

## Test the alert path

Send a test alert straight to Alertmanager; it reaches every configured
receiver within `group_wait` (30 s), and a "RESOLVED" message follows once it
is ended (within `group_interval`, 5 min):

```bash
AM=http://127.0.0.1:9093
now=$(date -u +%Y-%m-%dT%H:%M:%SZ); later=$(date -u -d '+10 min' +%Y-%m-%dT%H:%M:%SZ)
curl -s -XPOST -H 'Content-Type: application/json' $AM/api/v2/alerts -d "[{
  \"labels\": {\"alertname\": \"MonitoringTest\", \"severity\": \"warning\", \"component\": \"platform\"},
  \"annotations\": {\"summary\": \"Test alert from the operator\"},
  \"startsAt\": \"$now\", \"endsAt\": \"$later\"}]"
# end it:
curl -s -XPOST -H 'Content-Type: application/json' $AM/api/v2/alerts -d "[{
  \"labels\": {\"alertname\": \"MonitoringTest\", \"severity\": \"warning\", \"component\": \"platform\"},
  \"endsAt\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}]"
```

No message: `docker logs openctemio-obs-alertmanager-1` names the failing
integration (wrong token, webhook or chat id); see
[AlertDeliveryFailing](#alertdeliveryfailing).

## Routing, silences, maintenance

- Alerts with the same name and severity are sent as one message
  (`[FIRING:3] WARNING SensorsOffline`). A firing alert is repeated every hour
  (critical) or 12 hours (warning) until it resolves; resolving sends one
  message.
- The critical level of an alert hides its warning level. While `ApiDown` or
  `PostgresDown` fires, every alert computed from the API's metrics
  (`component=api`) is held back: they are consequences.
- Before planned work, silence in the Alertmanager UI (New silence, matcher
  e.g. `alertname=~"ApiDown|WebDown"`, a duration and a comment), or:
  `docker compose -p openctemio-obs exec alertmanager amtool silence add alertname=ApiDown --duration=30m --comment="deploy" --alertmanager.url=http://127.0.0.1:9093`.

## Alert runbooks

Each alert links here. Severity: **critical** = act now (outage or data at
risk), **warning** = act today.

### ApiDown

`GET /health` on the API failed for 2 minutes. Check `docker ps` (is the API
container running, restarting?), then `docker logs --tail 200 <api container>`.
A refusal to start with "database schema is behind" means migrations were not
applied (see [SchemaBehind](#schemabehind)). If Postgres or Redis is down, fix
that first.

### ApiScrapeFailing

The API answers `/health` but `/metrics` fails, so every API-derived alert is
blind. Almost always `METRICS_TOKEN` differs between the API and the
monitoring stack (the API answers 404 to a wrong token), or the API runs
without one. Set the same value on both and restart them. Prometheus
"Targets" page shows the error.

### WebDown

The web container does not serve `/login`. `docker logs <web container>`:
after a deploy, a build or module error is the usual cause; restart the web
container.

### GatewayDown

The public URL does not serve `/login` but the API and web may be fine: check
the gateway container, its certificate and DNS. Compare with
[WebDown](#webdown) and [ApiDown](#apidown).

### TlsCertExpiringSoon

A public-CA certificate expires within 14 days (warning) or 3 days
(critical): check the gateway log for renewal errors (DNS, port 80
reachability).

With `OBS_PUBLIC_PROBE_MODULE=http_2xx_internal_ca` the gateway's internal CA
issues 12-hour certificates and renews them itself, so the thresholds are 2
hours (warning) and 30 minutes (critical): renewal has stopped. Check the
gateway log and restart the gateway.

### ApiHigh5xxRate

More than 5% (warning) or 20% (critical) of API requests answer 5xx. Find the
routes: Prometheus `topk(5, sum by (path) (rate(http_requests_total{status=~"5.."}[5m])))`,
then the API log for those paths. Usually the database, a recent deploy, or a
panic ([ApiPanics](#apipanics)).

### ApiSlow

p95 latency above 2 s for 15 minutes. Check database load
([PostgresLongTransaction](#postgreslongtransaction),
[ApiDbPoolSaturated](#apidbpoolsaturated)), host CPU and memory, and the slow
request lines in the API log (`slow request`).

### ApiPanics

A code path panicked (a bug); the request or task failed, the process kept
running. `docker logs <api container> 2>&1 | grep -A2 "panic"` gives the
request id or task (the stack trace is logged outside production). File a
bug with the trace.

### ApiErrorLogBurst

A component logs more than 10 errors a minute. The alert names the component
(the logger's `controller`/`service`/`worker` attribute; `none` when the line
had none). `docker logs <api container> 2>&1 | grep level=ERROR | grep <component> | tail`.

### SchemaBehind

The running API ships a newer migration than the database has. Run the
migrations (`docs/deployment/safe-deploy-and-migrations.md`); in development
with hot reload the API does not migrate by itself.

### SchemaDirty

A migration failed half way and golang-migrate marked it dirty. Follow
"dirty-migration recovery" in `docs/deployment/safe-deploy-and-migrations.md`.

### OpsMetricsFailing

The API cannot read its platform-wide counts (the sensor, queue and outbox
alerts are blind). The API log has `operator metrics: reading the platform
counts failed` with the database error.

### ApiDbPoolSaturated

Over 90% of the API's database connections are in use. Look for long queries
or transactions ([PostgresLongTransaction](#postgreslongtransaction)) and
request spikes; raise the pool size only once the cause is known.

### ControllerErrors

A background controller (named in the alert) fails repeatedly. The API log
lines with `controller=<name>` say why.

### SensorsOffline

Active sensors stopped sending heartbeats. The Sensors page lists them. Check
the sensor host and container (`docker logs <sensor>`), its network path to
the gateway, and the key (expired or revoked keys also stop heartbeats).

### SensorConfigImpaired

Sensors report a configuration problem (impaired or blocked): missing tools,
capabilities the platform ignored, a local policy refusing work. The sensor's
Configuration tab lists the checks that fail.

### SensorsUnhardened

Tenant sensors have run unhardened for a day. They keep working (existing
installs are not cut off); each `kind` is one reason, and the Sensors page
shows a warning on each flagged sensor and a Security posture block in its
details:

- `policy_none`: no local policy, and none required (an install paired before
  policies were required), or a sensor whose SDK reports none. The network
  owner installs one from the Local policy tab of the install commands
  (`SENSOR_LOCAL_POLICY`).
- `pin_none`: the sensor's HTTPS client trusts the system trust store instead
  of a pinned platform CA. Set `SENSOR_CA_FINGERPRINT` (shown in the install
  commands).
- `network_unenforced`: tools run without network confinement. Run the sensor
  with `SENSOR_SANDBOX_NETWORK=required` and the shipped seccomp profile.
- `bearer_key`: the sensor authenticates with a bearer key instead of a
  key-bound identity. Pair it again with an enrollment token.

The posture is what the sensor reports about itself: the platform shows it and
alerts on it but never relaxes a check because of it.

### SensorSdkUnsupported

Sensors run an SDK older than `SENSOR_SDK_MIN_VERSION`. Upgrade them (install
command on the Sensors page).

### CommandQueueStuck

A sensor command has waited over 30 minutes. Either no sensor is online for
it (see [SensorsOffline](#sensorsoffline)), its zone has no sensor, or no
sensor has the tool. Scan details show the waiting step.

### ScanRunsStuck

Open scan runs are more than 10 minutes past their deadline: the scan timeout
controller is not ending them. Check `controller=scan-timeout` in the API log
and [ControllerErrors](#controllererrors).

### IngestBacklog

More than 200 ingest jobs wait for 30 minutes: results arrive faster than the
worker imports them, or the worker stopped (`controller=ingest-worker` in the
log). Findings appear late meanwhile.

### IngestJobsDead

Ingest jobs failed every retry; their results are not imported. The log line
`ingest: job processing failed ... dead=true` has the error.

### OutboxLagging

The oldest notification has waited over 15 minutes: the notification worker
is stopped or every channel fails. Check the API log for the outbox worker
and the channel errors.

### OutboxDeadLetters

Notifications gave up after their retries. Organization admins see them in
the notification delivery history; usually a channel's credentials changed.

### AutomationAutoPaused

The platform switched off an automation whose latest runs all failed. The
audit log has the event (`workflow.deactivated`, reason
`consecutive_failures`); the organization's admins fix and re-enable it.

### AutomationFailures

More than 20 automation runs failed in an hour across the platform: look for
a shared cause (an integration down, a recent change).

### AuditChainBreak

The audit log hash chain has a new break: an audit entry was changed or
removed outside the API. **Treat it as a security incident**: keep the
database as is (snapshot), find who had database access, compare with the
latest backup. The admin console shows the break.

### LoginFailureSpike

More than 50 failed password sign-ins in 5 minutes: password guessing or
credential stuffing. Accounts lock after repeated failures; check the source
addresses in the audit log (failed sign-ins) and block them at the edge.

### RateLimitSpike

The API refuses more than 60 requests a minute for rate limits. One client
floods it (block it), or a limit is too low for real traffic (raise
`RATE_LIMIT_*`).

### WebClientErrors

Browsers report errors. `chunk_load` right after a deploy usually means
cached pages ask for assets the new build no longer has (a reload fixes it;
many reports mean the deploy left the web in a bad state). `render` or
`unhandled` are bugs in the web console.

### PostgresDown

Postgres is unreachable (or refuses the exporter's login). `docker ps`,
`docker logs <postgres container>`. A full disk makes Postgres stop with
PANIC: see [HostDiskLow](#hostdisklow).

### PostgresTooManyConnections

Over 80% of `max_connections` used. Find the holders:
`SELECT usename, application_name, state, count(*) FROM pg_stat_activity GROUP BY 1,2,3 ORDER BY 4 DESC;`

### PostgresLongTransaction

A transaction has been open over 15 minutes; it holds locks and blocks
vacuum. `SELECT pid, usename, now() - xact_start AS age, state, left(query, 80) FROM pg_stat_activity WHERE xact_start IS NOT NULL ORDER BY age DESC LIMIT 5;`
End it with `SELECT pg_terminate_backend(<pid>);` when it is not a migration.

### PostgresDeadlocks

Postgres resolved deadlocks. A few are harmless; repeated ones point at a
code path taking locks in different orders: the Postgres log has both
statements.

### RedisDown

Redis is unreachable: sessions, rate limits and caches fail. `docker logs
<redis container>`; a full disk breaks its append-only file too.

### RedisMemoryHigh

Redis is above 90% of its `maxmemory` and starts evicting. Raise the limit or
find the keys that grow (`redis-cli --bigkeys`).

### BackupStale

No successful database backup in 26 hours. The alert reads a status file the
backup job writes for node-exporter's textfile collector. Add at the end of
the backup script (atomic write, `OBS_TEXTFILE_DIR`):

```bash
dir=/var/lib/node_exporter/textfile; tmp="$dir/openctem_backup.prom.$$"
{
  echo "openctem_backup_last_exit_code $rc"
  [ "$rc" -eq 0 ] && echo "openctem_backup_last_success_timestamp_seconds $(date +%s)"
} > "$tmp" && mv "$tmp" "$dir/openctem_backup.prom"
```

(keep the previous success timestamp when a run fails, e.g. by reading it
from the old file). Then check why the backups stopped (cron, disk space,
credentials).

### BackupFailed

The last backup run exited non-zero. Run the backup script by hand and read
its error.

### BackupMetricMissing

No backup status is reported at all: the backup job does not write the status
file yet (see [BackupStale](#backupstale)), or `OBS_TEXTFILE_DIR` points
elsewhere.

### HostDiskLow

A filesystem has under 12% free (warning) or 7% (critical). When the disk
fills Postgres stops with PANIC. `df -h`, then the usual consumers:
`docker system df`, container logs, old images and build caches, backups.
Never remove the database volume.

### HostDiskFillingFast

At the current rate a filesystem fills within a day. Find what grows
(`du -xh --max-depth=2 / | sort -h | tail`).

### HostMemoryLow

Under 10% (warning) or 5% (critical) memory available. `ps aux --sort=-rss | head`;
the kernel will start killing processes ([HostOomKill](#hostoomkill)).

### HostOomKill

The kernel killed a process for lack of memory. `journalctl -k | grep -i "killed process"`
names it. If it was a platform container, check that it came back.

### HostHighLoad

Load above 2 per CPU for 30 minutes. `top`; scans running on the same host
are a common cause.

### ContainerRestarting

A platform container restarted twice or more in 30 minutes (a crash loop).
`docker logs --tail 100 <name>` before it restarts again.

### ContainerOomKilled

A container hit its memory limit and was killed. Raise its limit or find the
leak; the container log shows what it was doing.

### ContainerMemoryNearLimit

A container uses over 90% of its memory limit for 10 minutes; it will be
OOM-killed soon.

### MonitoringTargetDown

Prometheus cannot scrape an exporter; the alerts built on it are blind.
`docker compose -p openctemio-obs ps` and the exporter's log.

### AlertDeliveryFailing

Alertmanager cannot deliver to Telegram or Slack (named in the alert). The
other channel receives this alert. `docker logs openctemio-obs-alertmanager-1`
gives the error: a revoked bot token, the bot removed from the group, a wrong
chat id, or a deleted Slack webhook.

### AlertRuleFailing

An alert rule fails to evaluate (Prometheus "Rules" page shows the error).
Fix the rule and run `deploy/observability/test/check-config.sh`.
