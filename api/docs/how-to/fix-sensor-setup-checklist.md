# Fix a sensor's setup checklist

A sensor checks its own setup when it starts and whenever a result changes:
is its state on a volume, are its scanners installed and working, can it
read the platform's CA certificate, does it inherit a proxy it should not,
is a local policy installed. It sends the results to the platform, which
shows them as the sensor's setup checklist and explains how to fix each
problem for your install type.

Design: [RFC-033 §11](../rfcs/RFC-033-sensor-manifest.md) and
[architecture/sensors.md](../architecture/sensors.md#config-report-the-setup-checklist-research26).

## Where to look

- **Sensors page.** The `config_health` chip on each sensor: `ok`,
  `attention` (a warning), `impaired` (a check failed) or `blocked` (a check
  failed that stops the sensor from doing any work). A sensor with a failed
  or warning check is also `degraded`, with the health reason
  `config_check_failed` or `config_check_warning`.
- **Sensor drawer, Setup & health.** The checklist, worst first: what the
  sensor saw, why it matters, and a fix.
- **API.** `GET /api/v1/sensors/{id}/config-report` (permission
  `sensors:read`) returns the same data.

## Fix a check

1. Open the failing or warning check. Read **why**: it names the setting or
   path the sensor reported.
2. Pick the tab of your install type: **env** (a shell or env file, also the
   lines to add to `docker run`), **compose** (Docker Compose) or **helm**
   (values for the `openctem` chart's `sensor:` block). A tab is missing when
   the fix does not apply to that install type or needs a value the sensor
   did not report.
3. Apply the snippet on the sensor host (or in your values file) and restart
   or upgrade the sensor. The snippets are text: the platform never changes
   the sensor's configuration itself.
4. The sensor runs its checks again at start and sends a new report. The
   check turns to `pass` within one heartbeat.

The values inside a snippet (paths, setting names) come from the sensor's
report and are quoted for the format, so a copied snippet does not run
anything it should not. The wording and the snippets themselves come only
from the platform.

## Common checks

| Check | What it means | Usual fix |
|---|---|---|
| `identity.state_persistent` | The sensor keeps its renewed API key in a directory that is not on a volume. Recreating the container loses the key. | Mount a volume at the state directory (`SENSOR_STATE_DIR`, default `/var/lib/openctem/state`); Helm: `sensor.state.persistence.enabled: true`. |
| `identity.key_renewal` `off_not_persistent` | Key renewal is off because the state is not kept. | Mount the state volume; then `PLATFORM_KEY_AUTORENEW=true` (Helm: `sensor.keyAutoRenew`). |
| `tool.<name>.binary` | The scanner is not installed, or it is installed but does not start (the excerpt shows its output). | Use an image that ships it (the default image carries semgrep, betterleaks, trivy and nuclei), or remove it from `SENSOR_TOOLS`. |
| `tools.available` `none` | No scanner is installed and allowed, so the sensor gets no scans. | Set `SENSOR_TOOLS` (Helm: `sensor.tools`) to scanners the image has. |
| `network.scan_proxy_inherit` `inherits_proxy` | `HTTPS_PROXY` and friends are set, so scanners send scan traffic through that proxy. | Say what you want: `SENSOR_SCAN_PROXY=direct`, or set it explicitly to keep the proxy. |
| `platform.tls` | `SSL_CERT_FILE`, `SSL_CERT_DIR` or `SENSOR_CA_CERT_FILE` points at a path the sensor cannot read, so TLS to the platform fails. | Mount the platform CA read-only at that path. |
| `runtime.oom_protect` `no_permission` | The sensor cannot ask the kernel to stop a scanner before itself under memory pressure. | Add the `SYS_RESOURCE` capability. |
| `policy.local` `absent` | No local policy on the sensor host. | The network owner installs one (Helm: `sensor.localPolicy.enabled: true`). |
| `policy.template_keys` `missing` | The local policy allows custom templates but no signing key is set, so every custom template is refused. | Set `SENSOR_TEMPLATE_SIGNING_KEYS` to the tenant's template signing public key. |
| `config.env_unknown`, `config.file_unknown_key` | A setting the sensor does not read (often a typo). | Rename it (the check suggests the closest name) or remove it. |
| `config.alias_deprecated`, `config.tool_retired` | An old name still works but is deprecated. | Use the new name the check gives. |

## Special cases

- **"Derived from the heartbeat."** The sensor is older than the release that
  sends a report. The platform shows what it can tell from the heartbeat
  (scanners reported as not installed, no scanner available, no local
  policy). Upgrade the sensor for the full checklist.
- **Stale.** The sensor's heartbeat no longer matches the last report it
  sent (`config_report_stale`): its configuration changed and the new report
  has not arrived, or it was downgraded. The platform asks the sensor for its
  report on the next heartbeat; restart the sensor if it stays stale.
- **Unknown checks.** A newer sensor may send checks this platform does not
  know yet. They are shown with their id and the sensor's own summary, and
  no fix; upgrade the platform for the explanation.
- **Secrets.** The checklist lists the settings the sensor declares and
  whether each is set and where it came from, never a value. The platform
  drops a value even if a sensor sends one.
