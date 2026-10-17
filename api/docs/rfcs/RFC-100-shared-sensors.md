# RFC-100: Shared sensors

| | |
|---|---|
| Status | Accepted (2026-10-15); S0 in review (#2308), S2 in review (#2325), S3 in review, the rest designed |
| Scope | api (schema, access policy, claim, enrollment, signer, quotas, console), web (console fleet page, tenant view), sdk-go (per-job isolation, target re-check), sensor (instance enrollment, isolation profile), helm-charts and compose (bundled sensor) |
| Architecture | [sensors.md](../architecture/sensors.md#shared-sensors-on-the-tenant-plane) |
| Amends | RFC-023 D14 (public targets only becomes a deployment default), RFC-022 (console owns the shared fleet), RFC-090 W11/W12 (shared-pool lanes replace `get_next_platform_job`) |
| Related | RFC-030 (pull, leases, fair share), RFC-032 (enrollment), RFC-034 (egress), RFC-040 (mutual distrust, signed jobs), RFC-052 (grants), RFC-054 §8.1 (domain proof), RFC-059 (transport v3), RFC-064 (entitlements and limits), RFC-065 §8 (program targets) |

## 1. Summary

A **shared sensor** belongs to the instance, not to an organization. Whoever
runs the instance operates it: the service operator on the hosted service,
the instance administrator on a self-hosted install. It scans for every
organization the instance allows, and no organization ever sees it as a node.
An **organization sensor** belongs to one organization, exactly as sensors do
today.

Shared sensors exist in every edition and are never a paid capability. The
hosted service differs only by defaults and by the limits its control plane
writes. A self-hosted install gets the same concept for its own needs: a
central scanner that serves several organizations (an MSSP, an enterprise
with business-unit organizations, a university), the sensor bundled with the
compose and Helm installs, and air-gapped sites.

"Platform sensor" is retired as a name. "Platform" keeps meaning the admin
plane (platform admin, platform settings).

## 2. Today (2026-10-15)

- One rule (`PlatformSensorsAllowed`) answers false for every organization,
  so no organization can use shared sensors. Nothing claims a shared job
  (`get_next_platform_job` has no caller), nothing creates a shared sensor
  (`SetPlatformSensor` has no caller), and the sensor binary has no shared
  mode. What exists is the policy and isolation shell: routing rules, the
  domain-proof setting, invisibility on the tenant plane, redaction of
  shared-sensor text, fair-share SQL.
- Three latent holes in that shell are closed by S0 (§11): an organization's
  own sensor could claim a job routed to shared sensors (live: all twelve
  such jobs ran on organization sensors); the insert trigger granted a
  shared sensor credentials, push ingest and tier 2; workflow steps reached
  shared sensors without the internal-target, proof and program checks.

## 3. Scopes

| Scope | Owner | Created by | Serves |
|---|---|---|---|
| `instance` (shared sensor) | the instance | instance administrator, in the console | every organization the access policy allows (§5), or one organization when dedicated |
| `organization` | one organization | an organization administrator (pairing, RFC-052) | that organization |

Narrower placement stays what it is: scan zones, sensor pinning and tool or
capability tags. A **dedicated** shared sensor is an instance sensor locked
to one organization (for a customer that needs its own scanner and egress
address but should not run it). A level between instance and organization
(business units) waits for a third real case.

### 3.1 Data model

- `sensors.scope text NOT NULL` with `CHECK (scope IN ('instance',
  'organization'))`, replacing `is_platform_sensor`.
- `sensors.tenant_id` becomes nullable, with `CHECK ((scope = 'instance') =
  (tenant_id IS NULL))`. The fake "operator's tenant" goes away: it is what
  let a shared row take that tenant's jobs through the tenant poll.
- The scope is fixed at creation: an organization sensor never becomes a
  shared one (its keys, grant and history would move to the instance);
  re-enroll instead.
- `sensors.dedicated_tenant_id uuid NULL` (only for `scope = 'instance'`).
- Every repository filter that says `NOT is_platform_sensor` says
  `scope = 'organization'`; the tenant-plane walk test still answers 404 for
  every shared sensor.
- Grants (`sensor_grants`) for an instance sensor have no `tenant_id`; the
  clamp trigger of S0 moves to `scope = 'instance'`.
- Commands keep `is_platform_job`. The holder of a shared job is
  `commands.sensor_id`, like every other job (S5), and
  `platform_sensor_id` is removed.

## 4. Mapping to the scope model of hosted CI runners

The model follows the scope hierarchy that has worked for CI runners at
scale, adapted to scanning:

| Pattern | Here |
|---|---|
| Runners at instance, group and project scope | `instance` and `organization` sensors; zones and pinning for narrower placement |
| One authentication token per runner, created by the scope's owner; no shared registration secret | single-use, short-lived instance enrollment token from the console (§7) |
| Tags select runners | tools, capabilities, zones and `region` |
| "Run untagged jobs" switch | per shared sensor: "accept unzoned public jobs" (pool) or "zone jobs only" |
| Protected runners take protected jobs only | "approved jobs only": signed jobs from approved scan definitions or above a trust level |
| Paused runner, maximum job timeout | console pause and drain, per-sensor maximum job duration |
| Instance runners on for new projects by default, per-group toggle | "Organizations without a decision" (§5), chosen explicitly when shared sensors are turned on (no implicit default), per-organization allow or deny, organization opt-out |
| Compute quota with a cost factor per runner type | generic per-organization limits (§10), per-tool weights later |
| Ephemeral VM per job on the hosted fleet | per-job isolation on shared sensors (§8) |

Not taken: paid quotas on self-managed installs (limits are free
everywhere), a shared registration secret, and a group-of-groups level.

## 5. Access

Three layers, all of which must allow:

1. **Instance switch** `shared_sensors.enabled` (console, super admin,
   step-up, audited). Off on every deployment until S0, S5 and S11 have
   landed (§11); then turning it on is an explicit administrator action, on
   the hosted service and on self-hosted installs alike.
2. **Default for organizations without a decision** `shared_sensors.new_orgs`,
   plus a **per-organization allow or deny** by the instance administrator
   (the entitlement deny key `shared_sensors`, RFC-064). A deny wins over the
   default. The default is **unset** until the administrator chooses, and
   unset refuses: turning the instance switch on requires choosing allow or
   deny for organizations without a decision **in the same action** (the API
   answers 400 `NEW_ORGS_CHOICE_REQUIRED` otherwise), so a switch-on alone
   never grants shared sensors to every organization (decision 2026-10-16,
   security first: explicit rather than an implicit default).
3. **Organization opt-out**: the organization owner may say "never send our
   scans to shared sensors" (data residency, allowlists, policy). Default:
   use them when available.

The default applies to every organization without an
administrator's decision. An organization does not keep a copy of the
default from the day it was created.

`PlatformSensorsAllowed` becomes this policy. Its refusal names the real
reason ("shared sensors are turned off on this instance", "your
organization opted out", "the instance administrator has not enabled shared
sensors for your organization") and never mentions an edition.

## 6. Deployment defaults

| Setting | Hosted service | Self-hosted |
|---|---|---|
| Shared sensors exist | the service's regional pools | none until the administrator enrolls one; the bundled compose/Helm sensor enrolls at instance scope |
| Organizations without a decision | chosen explicitly when the switch is turned on (unset refuses) | chosen explicitly when the switch is turned on (unset refuses) |
| Domain proof before shared sensors scan (RFC-054 §8.1) | **on** | off |
| Shared sensors may scan internal zones (§6.1) | **off** (public targets only) | on (only zones the administrator assigns) |
| Limits | written by the control plane per organization | none unless the administrator sets them |
| Credentials on shared sensors | never | off; the administrator may allow them per sensor, by reference only (RFC-040 §5.9) |

The hosted defaults come from the `MANAGED_SERVICE` environment setting,
which may change **defaults only**, never features: here the proof default
and the internal-zones default. A stored console value always wins. A
runbook step was rejected because a forgotten step fails open on a public
multi-tenant service.

### 6.1 Amendment of RFC-023 D14

D14 said shared scanners scan public targets only and never zones. That stays
the hosted default. On a self-hosted install the instance administrator may
create **instance scan zones** (ranges plus the shared sensors that serve
them) and assign each to organizations. An organization's internal target
then goes to a shared sensor only inside a zone assigned to that
organization; overlapping private ranges of different organizations are told
apart by the zone. The sensor-local policy (RFC-040 §5.7) lists the zone
ranges, so the sensor refuses anything else even if the platform were
compromised. Credentials stay off unless the administrator allows them per
sensor.

## 7. Enrollment

- The console issues a **single-use instance enrollment token** (super
  admin, step-up, a reason, admin audit; lifetime ≤ 1 hour; shown once).
- The sensor enrolls with it exactly as an organization sensor pairs
  (RFC-032 key-bound identity, RFC-059 mTLS v3), and the row gets
  `scope = 'instance'`, no tenant, `trust_level = 'trusted'` and the
  least-privilege grant of S0.
- The compose and Helm installs read the token from a secret
  (`SENSOR_INSTANCE_ENROLLMENT_TOKEN`) generated by the install, so the
  bundled sensor comes up as a shared sensor (P11).
- sdk-go `pkg/platform` (routes the core never served) is deprecated and
  removed; shared sensors use the same v2/v3 protocol as every sensor.

## 8. Isolation on a shared sensor

| Concern | Design |
|---|---|
| Tenant plane | unchanged: every `/api/v1/sensors/{id}` route answers 404, lists exclude shared rows, jobs show no sensor identity, text is redacted, sightings say `sensor:platform` |
| Claim | only the shared claim path (S5) hands shared jobs to shared sensors; an organization sensor never takes one (S0) |
| Per-job isolation (S11) | every job in a fresh, private workdir and process sandbox (unprivileged UID, rlimits, seccomp), destroyed after the job; no writable cache shared between jobs except signed public content; outbox entries tagged with the job and its tenant; egress to private, loopback, link-local and metadata addresses dropped at the network layer unless the job's zone allows the range. The mechanisms live in sdk-go core, the sensor only wires them |
| Name resolution (G8) | the API resolves every host name of a job bound for shared sensors and refuses it when any address is private, loopback, link-local, CGNAT or a metadata address. The sensor resolves again right before connecting and pins the address it checked, so a name re-bound between the two checks is refused there (DNS rebinding) |
| Results | written as T1, into the tenant of the job the sensor holds (BOLA per job); never unsolicited push (grant clamp) |
| Content | public, signed content only; no per-tenant rulesets on a shared box |
| Credentials | never on the hosted service; self-hosted off unless allowed per sensor, by reference |

### 8.1 Signed jobs for a sensor that serves many tenants (G9)

Tenant signing keys (RFC-040 §5.6) exclude shared sensors, and a shared
sensor must not trust any tenant's key set. Design:

- An **instance key set**, separate from every tenant key set, under the
  instance's offline root (K3). The signer signs shared jobs with an online
  key of that set only, and refuses to sign a shared job with a tenant key or
  a tenant job with the instance key.
- The envelope is the RFC-040 job document. For shared jobs it must carry
  `tenant_id`, `sensor_id` (the claiming shared sensor), `command_id`,
  `lease_epoch`, `tool`, `tier`, `targets`, `zone` (for instance zones),
  `exclusions`, `expires_at` and a `nonce`; the signer's ledger checks the
  targets against the tenant's scope and the instance policy (public only, or
  inside a zone assigned to that tenant).
- The shared sensor pins the instance root at enrollment (or from its local
  policy file), verifies every job, refuses one whose `sensor_id` is not its
  own or whose nonce it has seen, and tags every result with the envelope's
  `tenant_id` and `command_id`. The API accepts a result only for a command
  the sensor holds under that lease epoch, so a compromised shared sensor
  cannot move results across tenants.

## 9. Abuse controls and egress identity

- Always on: deny list, scope gate, exclusions, tier ceilings, per-host
  politeness, admin audit.
- Hosted defaults: proof on, intrusive probes need proof everywhere, a T1-safe
  profile for unclassified assets, per-organization limits, an
  acceptable-use clause and an abuse contact, an identifying User-Agent,
  reverse DNS and an information page on the scanner addresses, a
  per-organization kill switch (the deny of §5) and anomaly alerts (many
  distinct registrable domains, failure spikes, deny-list hits).
- **Egress addresses are published to tenants** (G11): the console stores the
  egress addresses (or ranges) for every region and per region
  (`/api/v1/admin/settings/shared-sensors/egress`, super admin, step-up,
  reason, audited); only public addresses are accepted (ctis `addrscope`
  refuses every internal range, so the list never discloses the operator's
  network). Organization members that may use shared sensors see them in the
  shared sensors card (`egress` in `GET /api/v1/platform/scanning`) so they
  can allowlist the scanners. No sensor id, name, version or load is shown.

## 10. Limits

Shared compute is a real cost on the hosted service. Limits are the generic
per-organization limits of the entitlement service (RFC-064), read by key,
never by plan name: `platform_scans_per_day` (shared scans started per UTC
day) and `platform_scans_concurrent` (shared jobs queued or running). The
trigger refuses a scan over the daily limit with the reason; the claim path
does not hand an organization more concurrent shared jobs than its limit.
Self-hosted installs have no limit unless the administrator sets one. Queued
work finishes after a downgrade. Per-tool weights come when a third tool type
needs them.

## 11. Rollout and the access gate

| PR | Content | State |
|---|---|---|
| S0 | tenant claims skip shared jobs; least-privilege grant clamp; the trigger's target check on every workflow step | in review (#2308) |
| S1 | this RFC | this PR |
| S2 | `sensors.scope`, nullable `tenant_id`, drop `is_platform_sensor`; scope fixed at creation; a shared sensor's grant limited to scan, validate and retest | in review (#2325) |
| S3 | access policy (§5) with the instance switch off everywhere: instance setting, per-organization allow or deny, owner opt-out, rollout gate in code | in review |
| S4 | instance enrollment token, bundled sensor at instance scope | designed |
| S5 | shared claim path (fair share, per-organization concurrency limit, region, untagged switch, isolation capability); remove `get_next_platform_job` ([architecture](../architecture/sensors.md#the-shared-claim-path)); the approved-jobs-only flag waits for the instance signer (S6) | in review |
| S5a | results of a shared sensor bound to the job it holds under its lease epoch, written into the command's organization; no push ([architecture](../architecture/sensor-result-binding.md#shared-sensors)) | in review |
| S6 | instance key set and shared-job envelope | designed |
| S7 | limits enforced at trigger and claim | designed |
| S8 | console "Shared sensors" fleet page, audited job view with a reason | designed |
| S9 | tenant view renamed "Shared sensors" / "Organization sensors", egress addresses (console + tenant view), opt-out linked from the card | in review |
| S10 | instance scan zones assigned to organizations | designed |
| S11 | per-job isolation and private-range egress drop in sdk-go, used by the sensor | designed |
| S12 | `MANAGED_SERVICE` defaults, anomaly alerts, scanner identity | designed |
| G8 | API-side name resolution for shared jobs, sensor re-check | designed |

**Gate.** No deployment enables shared sensors before S0, S5 and S11 have
landed. Until then `PlatformSensorsAllowed` keeps answering false. After
them, access needs the explicit console action of §5 (`shared_sensors.enabled`),
which is off by default everywhere.

## 12. Administrator visibility

Instance administrators see aggregates freely: fleet health, regions, queue
depth per lane, per-organization usage counts. A job's targets and logs only
through an audited view that asks for a reason (the pattern of the
platform-user view). Results and findings never.

## 13. Threat model

| Threat | Control |
|---|---|
| A tenant reaches another tenant's data through a shared sensor | no tenant route to shared sensors; per-job sandbox wiped after the job; no tenant credentials or rulesets on the box; results bound to the job's tenant and lease |
| A compromised shared sensor writes into a tenant | it can write only results of a job it holds, as T1, never push (grant clamp); signed jobs bind tenant and sensor |
| A compromised core sends a shared sensor somewhere it must not go | signer ledger and sensor-local policy (public only, or the assigned zone's ranges); private-range egress drop |
| A tenant points the operator's addresses at third parties | proof (hosted default), deny list, limits, kill switch, anomaly alerts, published scanner identity |
| A name that resolves inside (or re-binds) | API resolution check, sensor re-check with the pinned address, network-layer drop |
| An organization's own sensor takes a shared job, or a shared row takes a tenant's jobs | S0 claim predicate; S2 removes the fake home tenant |
| An instance administrator reads tenant results | metadata only; targets and logs through an audited reason view |
