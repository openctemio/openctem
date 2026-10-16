### Security: hosted-service defaults and anomaly alerts for shared sensors

- New environment setting `MANAGED_SERVICE` (default `false`), for a hosted multi-tenant service only. It changes two defaults, never a feature or a stored value (RFC-100 §6):
  - "Require a verified domain before platform sensors scan a target" defaults on (off on a self-hosted install);
  - the new setting "Shared sensors may scan internal zones" defaults off (on on a self-hosted install).
  A value saved in the admin console always wins. An unreadable stored value fails closed (proof required, internal zones refused).
- Admin console, System > Platform scanning: a card for "Shared sensors may scan internal zones" (`GET/PUT /api/v1/admin/settings/shared-sensor-internal-zones`). Each on/off card says which deployment default applies until a value is saved; `GET /api/v1/admin/settings/platform-sensor-proof` returns `default` too. Turning internal zones on assigns no zone.
- Anomaly alerts on shared sensor use (RFC-100 §9). Three counts per organization per UTC day: distinct registrable domains sent to shared sensors, failed shared jobs, deny-list hits. The first time a count reaches its threshold that day:
  - the metric `shared_sensor_anomalies_total{signal}` goes up;
  - an admin audit row `organization.shared_sensor_anomaly` (severity high) names the organization;
  - every administrator is emailed.
  Events are counted in `shared_sensor_signal_events_total{signal}`. Counters live in Redis, keep no target and expire after two days. Without Redis the signals are off; they never block a scan.
- Thresholds: `GET/PUT /api/v1/admin/settings/shared-sensor-anomaly` and a card on the same page. Defaults are 25 domains, 50 failures and 5 deny-list hits per day; 0 turns a signal off.
- Changes to either setting need a super admin, a reason and a route-level step-up (a fresh authenticator code). Each change gets a critical admin audit row, and the other administrators are emailed.
- Scanner identity guidance for operators (User-Agent, reverse DNS, information page, separate egress addresses) in `docs/architecture/sensors.md`.
- Upgrade: no migration. A hosted service sets `MANAGED_SERVICE=true`. A deployment that already saved the proof setting keeps its stored value.
