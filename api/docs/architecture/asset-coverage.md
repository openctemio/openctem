# Asset coverage

Design: [RFC-093](../rfcs/RFC-093-asset-coverage.md).

Every asset gets every capability its type needs, and a pair that goes
uncovered is visible. Three parts:

| Part | Where |
|---|---|
| **Policy**: per type, the capabilities it needs, how often, the facts that must hold (`resolves`, `web_port`, `web_port_or_unscanned`, `scope_entry`, `no_named_twin`) and the type a run must produce | `configs/asset-types.yaml` (`coverage:`), read with `coverage.Rules()` / `coverage.RulesFor()` |
| **Ledger**: one row per asset, capability and vantage: state, reason, last attempt and success, outcome, next due | table `asset_coverage`, `internal/infra/postgres/asset_coverage_repository.go` |
| **Loop**: the `asset-coverage` controller (one replica, every `ASSET_COVERAGE_INTERVAL`) | `internal/app/coverage` |

## States

`due` → `queued` → `covered` | `failed`; `blocked` (scope gate, guardrail,
placement or budget; the reason names which; never a gap), `paused` (the
capability cannot run for the organization now, with a readiness reason; a
window, hold or switch), `not_applicable` (a precondition does not hold; the reason
names it). A pair is a **gap** when it applies and has gone without a success
for more than twice its cadence.

## Reconcile

For each tenant with active assets and each rule, one statement adds the
missing rows (due now, or not applicable with the failing predicate) and
flips rows whose precondition changed. A core type's rule does not apply to
its alias sub-types (an `open_port` follows its own rules, not `service`'s).
Idempotent; bound to the tenant.

## Explanation

`GET /api/v1/assets/{id}/coverage` (`assets:read`, data scope by id: out of
scope is 404): one entry per rule of the asset's type (a rule with no row is
`due` / `not_planned`), then any other ledger row of the asset (platform
checks such as `dns.dangling`, connectors).

## Planning and settlement

Each pass, per tenant, after reconciling:

1. **Settle** every finished run that holds `queued` pairs, **per target**:
   a step may end with more tasks than chunks (claim-time splits, follow-ups
   of unfinished targets), so each pair is settled from what happened to its
   own target across every task of the run (`target_outcomes`, read against
   the task's own targets). `done` → `covered` (`ok`, or `no_output` when
   the rule expects a web origin and none of the asset was observed since it
   was queued; a target the sensor reported unreached fails as
   `unreachable`); `failed` keeps its class (`unreachable`, `timeout`,
   `tool_error`, `egress_refused`); `skipped` → `blocked` with its class; a
   task without outcomes covers its targets when it completed and fails them
   with its error otherwise; the best verdict across tasks wins (a follow-up
   that finished a target covers it). The run's own unfinished targets
   (including a connector's) fail as `unfinished`; a target no task carried
   fails as `not_dispatched` with the run's error. Failed pairs are due
   again after 1 h doubled per failure (at most the cadence, at most a day);
   a run not finished after a day fails its pairs as `stalled`. A
   **target-side** outcome (`unreachable`, `timeout`: the target did not
   answer, not a sensor, tool or platform failure) is an observation, not a
   failure: the pair is `paused` with the outcome as its reason and
   rechecked after 1 day, then 3 days, then 7 days and weekly from then on
   (consecutive target-side observations; jittered). The recheck runs the
   capability again; any success makes the pair covered and clears the
   streak. A paused target-side pair never counts as "keeps failing", but it
   still applies: once it has had no success for twice the cadence it is a
   gap, so a host that went dark shows in the gaps and their alert.
2. **Plan**, when the organization has automatic coverage on (Scoping >
   Settings, `auto_coverage`; default on, except while the scan approval
   mode in force is Strict, until the organization turns it on): for
   each stage capability of the policy (never an intrusive one; platform
   checks run on their own schedule), take up to 200 pairs whose time has
   come (priority, then oldest): `due`, `failed` after its back-off,
   `covered` past its cadence, `blocked` past its recheck time. When one of
   them is due now, the batch also takes pairs due within the next tenth of
   the cadence (at most an hour), so one run carries them instead of several
   one-target runs; when none is due now, nothing starts. All within the
   tenant's daily budget
   (`ASSET_COVERAGE_DAILY_BUDGET`, default 5000 attempts per 24 h), and call
   `scan.Service.StartCoverage`: the targets pass the one dispatch gate as
   the system (scope entries only) at the capability's tier; refused targets
   become `blocked` with the gate's code (rechecked after 6 h); the rest run
   on the tenant's reused ad-hoc scan "Continuous coverage: <capability>"
   (tag `auto-coverage`) with the stage's default tool, and become `queued`.
   While that scan still has an active run the batch waits (one run per
   capability and tenant at a time: back-pressure).

**Readiness before runs.** Before a capability's batch becomes a run, the
planner asks once per pass whether the capability could run for the
organization at all. The first failing check is the reason:

| Reason | Check |
|---|---|
| `policy_disabled` | the capability's default tool is switched off for the organization; or the trigger refused for an organization policy (scan approval, a window that never opens, the managed scan paused) |
| `no_scope` | the organization has no active, unexpired scope entry (the gate would refuse every target) |
| `tool_missing` | no sensor of the organization reports the tool |
| `tool_not_allowed` | sensors report the tool, but their grant or local policy does not allow it |
| `sensor_offline` | sensors with the tool exist and none takes work now |
| `sensor_outdated` | every online sensor with the tool reports a version below the catalog's minimum |
| `no_eligible_sensor` | no online sensor of the organization at all, or no zone that can place the run |
| `credentials_missing`, `quota_exhausted` | reserved (no capability declares a credential yet; coverage runs need an organization sensor) |

When a capability is not ready: no run, no blocked run, no gate call. Its
pairs whose time has come are paused with the reason in one statement, and
a pair already paused for another readiness reason takes the new one (a
pair paused for the same reason is not written again). On the first pass
where the capability is ready, its paused pairs become due and run in that
pass. A refusal of the whole batch by the trigger that means the same thing
(a sensor went offline between the check and the trigger) pauses the
capability with the mapped reason and retries after 30 minutes; any other
refusal of the whole batch (about its targets) blocks the batch's pairs
with the code. Coverage triggers never record blocked runs. The checks read
only the organization's own catalog, sensors and scope entries; a reason
never names another organization's sensor. Readiness only narrows: a ready
capability still passes every trigger and claim-time check.

**Due times are spread.** A covered pair is due again after its cadence
and a blocked pair after its 6 h recheck, each stretched by the pair's own
fixed jitter of 0 to 10 % (from md5 of the asset id and capability, the
same in Go and SQL), so pairs settled together drift apart and a restart
does not re-align them. A new pair, or one whose precondition holds again,
is due at once. A blocked or paused pair whose precondition stops holding
becomes `not_applicable` like any other.

**Passive capabilities and zones.** A passive capability (`resolve.dns`,
`lookup.rdap`, `lookup.asn`, `discover.subdomains`) sends no traffic to
its target. For an organization with scan zones, its public names skip
zone routing in the gate and at the trigger. A public name is registrable
under an ICANN public suffix, and none of the addresses it resolves to from
the platform is private or denied. So a public name that stopped resolving
is no longer refused `unresolved` or `zone_none`; its DNS re-check runs.
Internal names (a private answer, a non-public suffix, a special-use name such as home.arpa, local, localhost, internal, test, invalid, onion or example) and addresses keep
zone routing. One run carries either public names or routed targets: the
group of the batch's oldest target runs, and the other group stays due for
the next batch. Only the coverage run's own trigger can skip zone routing
(an unexported context marker), and every other gate check still applies.
Without zones, or for an active capability, nothing changes.

**HTTP probe on names.** A subdomain is probed only when it resolves and
is worth a probe (`web_port_or_unscanned`): an address it resolves to has
an active open port in the web port set, a web origin of the name
(`https://<name>` or `http://<name>`) was seen, or its ports are still
unknown (no port scan of the name or its addresses has succeeded and none
of its addresses has an open port on record). A name whose port scan found
no web port is `not_applicable` until one appears; reconcile then makes it
due again.

**Template scans on web services.** A web service reached by an IPv4
address (`https://203.0.113.10:8443`) is `not_applicable` for
`vuln.templates` with reason `no_named_twin` when an active web service
reached by a host name serves the same address on the same port (its
probe's `ip_addresses` and `port`): a named virtual host or a CDN-fronted
application answers its bare address with a default page, so the checks
run once, on the named service, with the right Host and SNI. An address
service with no named twin is still scanned. Reconcile makes it due again
when the named service goes away.

An open port is addressed as `host:port`; names and origins by name.
With the loop on, automatic enrichment of new assets is off: the loop
resolves and looks up every asset its policy names.

**Runs no sensor takes (`not_claimed`).** The readiness check sees
whether a sensor *could* take a capability's work; it cannot see every
reason the claim or a sensor's dispatch gate (grant, local policy,
intensity) keeps it. A coverage run whose step ends `NO_SENSOR` (no sensor
took its work before the run's deadline) counts on the capability's hold
(`asset_coverage_holds`, one row per tenant and capability); any other
finished run resets the count, a stalled one leaves it. At 3 runs in a row
the capability is paused with readiness reason `not_claimed`: its pairs
whose time has come, its failed pairs and pairs paused for another
readiness reason, until the probe time, and newly due pairs join the pause
on each pass. A live readiness reason still comes first. The pause lifts:

- when the tenant's sensor fleet changes: a hash of its organization
  sensors (state, tools, capabilities, local policy state, digest and kill
  switch, unzoned jobs), their grant versions, its zone assignments, its
  shared-fleet setting and the platform sensors' state and tools. It never
  reads heartbeats, health or load, so it moves on an administrator's or a
  sensor report's change, not every minute. The hash is computed and
  compared on the server only;
- at the probe time: 2 h after the third unclaimed run, doubled for each
  further one, at most 48 h (`NotClaimedRetry`).

Either way exactly one run goes (the probe time moves on as it starts). If
no sensor takes it either, the capability pauses again with the longer
wait; a run a sensor takes resets the hold. A fingerprint that cannot be
read is recorded empty: the pause then holds until the probe. The pause
raises the usual `readiness` alert ("Coverage paused: resolve.dns ... no
sensor took its last runs") with a link to the sensors, and the asset's
coverage shows the pair paused with that reason.

## Gap detection

After planning (tenants with automatic coverage on), at most every 15
minutes per tenant, the loop reads one health line per capability:
applicable pairs, gaps (no success for more than twice the cadence), pairs
failing 3 or more times in a row, and pairs settled in the last 24 h with
and without the expected output. It raises:

| Kind | When |
|---|---|
| `gap` | any gap |
| `output_drop` | no expected output over at least 20 settled inputs in 24 h (a broken or blocked tool) |
| `failing` | a pair failed 3 or more times in a row (not for platform checks `dns.*`: a single asset's answer is shown on that asset) |
| `readiness` | pairs are paused for a readiness reason (the reason is part of the key) |

Alerts are sent **on change**, never on a timer. Each key (capability,
kind, reason) has a row in `asset_coverage_alerts` (tenant-scoped): an alert
goes out when its condition appears, or when its count doubles or halves
since it was last sent. A condition that clears and comes back within a day
comes back silently. Several changes in one pass go out as one digest, at
most one digest per tenant per day; changes held by that limit stay
pending and go out with the next digest. Each message names the action and
links to where it is taken: the scope page for `no_scope`, the sensors page
for a sensor reason, Settings > Scanning > Tools for a tool or policy
reason, the assets for gaps. The message goes to the tenant's active
administrators in-app (`coverage_gap`) and to its integrations (event
`coverage_gap`, default-on for new integrations, not severity-filtered).
It carries counts and capability names only, never a host name. The state
is written before the message is sent, so restarts and replicas do not
repeat it, and a send that fails is logged, not retried every pass. The
operator sees fleet-wide aggregates with no tenant label:
`openctem_asset_coverage_gap_pairs{capability}` and
`openctem_asset_coverage_alerts_total{kind,capability}`.

## Other writers

- DNS checks (`internal/app/easmdns`): rows `dns.dangling` and `dns.email`.
- Connector rotation (`internal/app/scancoverage`): rows `network_va.connector`.
