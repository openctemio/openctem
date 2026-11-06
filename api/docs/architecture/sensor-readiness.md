# Sensor readiness checklist

`GET /api/v1/sensors/{id}/readiness` (`sensors:read`) answers one question
for a sensor of the caller's organization: what still stops it from
scanning. Design: research note 466 (decision D10). Code:
`internal/app/sensor/readiness.go`, handler
`internal/infra/http/handler/sensor_readiness_handler.go`, web
`features/sensors/components/sensor-readiness.tsx`.

The checklist only reads what the platform already knows (the sensor row,
its grant, its last local policy report, the organization's scan zones and
scope entries, its setup checklist) and changes nothing. Every fix goes
through the page and gate it belongs to.

## Items, in fix order

| Key | From | States | Fix (permission) |
|---|---|---|---|
| `online` | sensor status, health, first heartbeat | ok, waiting, blocked | `show_install` (host) |
| `trusted` | grant trust level | ok, blocked, unknown | `promote` (`sensors:grant:widen`, with the grant's step-up and audit) |
| `private_targets` | local policy report summary `allow_private` | ok, blocked, unknown, not_applicable | `enable_private`: the host line `SENSOR_ALLOW_PRIVATE_TARGETS=1` |
| `kill_switch` | local policy report `kill_switch` | ok, blocked, unknown | `kill_switch_off`: remove `/etc/openctem/STOP` |
| `networks` | the zones the sensor is assigned to | ok (count), blocked, unknown, not_applicable | `add_zone` (`sensors:zones:write`) |
| `scope` | private ranges of those zones against active and pending address entries | ok, blocked (count, patterns), waiting (count), unknown, not_applicable | `add_scope` (`attack_surface:scope:write`), through the scope service and its approvals |
| `sandbox` | setup checklist `runtime.sandbox_network` | ok, blocked, unknown | `sandbox_docs`: the host requirements guide |

- Private-network items apply when the grant may scan any network
  (`target_network = any` with scan jobs) or the sensor is in a zone with a
  private range; an internet-only sensor reads `not_applicable`.
- `private_targets` is `unknown` while the sensor reports the switch only
  inside an enforced local policy; once every report carries it, the item
  becomes exact without an API change.
- `scope` counts a zone range as covered when one active address entry
  (`cidr`, `ip_address`, `ip_range`) holds all of it; a range covered only
  by a pending entry is `waiting` (someone else must approve it). More than
  2000 address entries read `unknown`.
- `sandbox` reads the setup checklist, which holds host details, only for a
  caller with `sensors:write`; for anyone else it is `unknown` and does not
  make the sensor "not ready".
- `ready` is true when no item is blocked, waiting or unknown (the sandbox
  excepted as above).
- Each fix says whether the caller holds its permission (`allowed`); the
  console shows who may fix it instead of a button. The API stays the only
  authority for every fix.

## Security

- Tenant from the session; the sensor is read with the tenant
  (`GetSensor`), and another organization's sensor, an unknown id and a
  shared sensor answer 404 (route test `TestSensorReadiness_Route_DB`).
- Reads only; no fix runs from this route.
- The answer names no scope entry, zone id or host setting: states, counts,
  the zone ranges that are not in scope and fixed host lines.
- Data scope: configuration of the organization's own sensors
  (`/api/v1/sensors`, classified `config`).

## Where it shows

The sensor sheet (overview), the end of Add sensor (once approved) and New
scan (review step, the sensors of the chosen zone, blockers only).

The scan dry run keeps its own refusals with fixes; the codes
`zone_sensor_new` and `zone_sensor_no_private` (planned) will name the same
causes there.
