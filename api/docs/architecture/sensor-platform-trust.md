# Sensor ↔ platform trust

> Design: [RFC-040](../rfcs/RFC-040-platform-sensor-mutual-distrust.md). Related:
> [sensors.md](sensors.md), [agent-identity.md](agent-identity.md),
> [sensor-pairing.md](sensor-pairing.md), [sensor-result-binding.md](sensor-result-binding.md),
> [scan-zones.md](scan-zones.md), RFC-023, RFC-031, RFC-032, RFC-034, RFC-038,
> RFC-052.

The goal is **mutual distrust**: compromising one side must not be enough to
exploit the other.

- A compromised sensor (or a stolen sensor key) must not be able to attack the
  platform or other tenants.
- A compromised platform (web, API or database) must not be able to weaponize
  sensors against targets their network owner did not allow.

## Controls

The controls are grouped as in RFC-040. Each row names where the control lives;
the RFC holds the design and phase plan.

### Sensor → platform

| Control | Where |
|---|---|
| Per-sensor identity, short-lived self-renewed keys, instant revocation | [agent-identity.md](agent-identity.md); key-bound identity and pairing: RFC-032, RFC-052, [sensor-pairing.md](sensor-pairing.md) |
| Tenant taken from authentication, never from the request body | sensor authenticator on `/api/v2/sensor/*` |
| Sensor credentials accepted only on sensor routes, user credentials only on user routes | `internal/infra/http/routes/sensor_v2.go`, `middleware/apikey_auth.go` |
| Per-sensor job authorization: poll and claim scoped by tenant, sensor pin, zone, tool and capability; per-sensor grants | [scan-zones.md](scan-zones.md), RFC-052 |
| Results bound to the job that produced them; unsolicited reports limited or quarantined | [sensor-result-binding.md](sensor-result-binding.md) |
| Strict result parsing: schema validation, size and depth limits, string sanitisation, output encoding in the console, tickets and notifications | `pkg/sensorproto/v2`, `internal/app/ingest`, [web security architecture](../../../web/docs/security-architecture.md) |
| Separate sensor gateway and isolated ingest workers | **Planned** (RFC-040 §5.1, §5.4) |

### Platform → sensor

| Control | Where |
|---|---|
| Declarative jobs only, never shell; signed custom-template manifests | sdk-go command poller; RFC-040 §5.8 |
| Platform-side scope check before dispatch; scan targets limited to what the actor may act on | [active-probe-gate.md](active-probe-gate.md) |
| Sensor-local, read-only policy set by the network owner (allowed ranges, ports, check types, kill switch); the platform stops dispatching jobs a sensor would refuse | [sensors.md](sensors.md#sensor-local-policy-rfc-040-57) |
| Scan credentials held by the sensor, referenced by the platform | RFC-040 §5.9, RFC-032 |
| Jobs signed by a separate signing service, with nonce and sequence against replay | **Planned** (RFC-040 §5.6) |
| Two-person approval for scope widening | **Planned** (RFC-040 §5.6) |

### Both directions

| Control | Where |
|---|---|
| Audit of scope, exclusions, tools, scanner templates, scans and commands; tamper-evident audit chain | [audit-hash-chain.md](audit-hash-chain.md) |
| Hardened sensor images (non-root, minimal) and install snippets | sensor repository, RFC-040 §5.10 |
| Anomaly alerts on scope changes and unusual sensor activity | **Planned** (RFC-040 §5.11) |

## Reporting a weakness

Report a suspected weakness in these controls privately, as described in the
[security policy](../../../SECURITY.md).
