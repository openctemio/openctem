# RFC-089: Reachability-aware routing

| | |
|---|---|
| Status | Draft (2026-10-13); steps 1–4 and 6 in progress, the rest designed |
| Scope | sdk-go (`pkg/reach`, `pkg/netctx`, manifest `network` member, conformance), sensor (tool parsers, network report), api (claim predicates, eligibility reasons, networks, learned reach, vantage, run coverage), web (sensor Network tab, routing preview) |
| Architecture | [scan-zones.md](../architecture/scan-zones.md), [sensors.md](../architecture/sensors.md), [sensor-result-binding.md](../architecture/sensor-result-binding.md) |
| Related | RFC-023 (zones; D15 networks), RFC-030 (pull, eligibility as a filter, D11 soft affinity), RFC-033 (sensor manifest), RFC-034 (egress profiles), RFC-040 (mutual distrust, local policy), RFC-046 §7 (failure codes, partial), RFC-060 (tool network confinement), RFC-074 (coverage gaps), RFC-088 (typed work units), research/118, research/119, research/120 |

## 1. Summary

Sensors sit on the internet, inside sites, or both. A scan's targets must go
to a sensor that can reach them; when none can, the run must say so.

Today a target goes to the narrowest zone whose range holds it, a host name by
the addresses the **platform's** resolver returns, and a public target to the
default zone or to any sensor of the tenant. Three facts are recorded nowhere:

- whether a sensor can reach the internet (directly, only through a proxy, or
  not at all);
- which networks it actually sits on;
- whether its last attempt at a target got through.

The damaging failure is silent. An internal-only sensor claims an unzoned
internet job, every connect times out, the port scanner reports "no open
ports" and the step is **completed with zero results**, which reads as
"nothing exposed". Overlapping private ranges at two sites cannot be modelled
at all: zones may overlap, ties break by zone name, and an asset has no
network context.

This RFC adds four layers, each with a clear owner:

1. **Network self-description** in the sdk-go core (`pkg/netctx`): declared
   facts (by the host owner), detected facts (by the SDK), a fingerprint; sent
   in the sensor manifest and re-sent on change.
2. **Per-target reach outcomes** in the sdk-go core (`pkg/reach`): every
   network error toward a target is classified, and every job result carries a
   bounded per-block reach summary.
3. **A routing step inside the eligibility function** (research/119 E1):
   network context per work unit, self-narrowing from the sensor's own report,
   preferences from learned evidence; overlapping private ranges told apart by
   a **network**.
4. **"Unreachable is not success"**: a step whose targets could not be reached
   fails or ends partial with `TARGET_UNREACHABLE`, never completed with 0
   results.

**The rule.** Authorization stays scope + grant + zone membership + local
policy, fail closed. Reachability only **removes** work from the sensor that
reported it cannot reach it, or **orders** sensors that are already
authorized. Anything that would **add** work (joining a zone, a new network, a
new range) is a suggestion an administrator confirms.

## 2. Terms

| Term | Meaning |
|---|---|
| Network | A tenant-owned address namespace and DNS view: a site, a VPC, a cluster. Every tenant has an implicit **internet** network (public addresses, public DNS). A single-site tenant never sees networks: its private space is the **default network**, created with the first zone. |
| Zone | Unchanged (RFC-023): ranges inside one network plus the sensors that may scan them. |
| Reach | Whether a sensor can open a path to a unit. Sources: **declared** (host owner or administrator), **detected** (SDK), **learned** (job outcomes). |
| Vantage | Where a result was observed from: `{network, kind: internal \| external}`. Stamped by the platform from the command, never read from a sensor's result body. |
| Block | The covering prefix used to aggregate reach outcomes: /24 for IPv4, /64 for IPv6. |

## 3. Use cases

| # | Case | Expected routing | Decided by |
|---|---|---|---|
| R1 | External-only sensor | Internet units only; preferred external vantage | Detected |
| R2 | Internal-only, no internet egress | Its site's units; never internet units | Detected (narrowing) + declared site |
| R2b | Internal, internet only through a proxy | Private units direct; internet units only for proxy-capable tools, never raw-socket tools | Detected + tool descriptor (`proxy: ignores`) |
| R3 | Dual-homed (DMZ) | Both; internal vantage for its site, external only when no better external sensor | Detected + declared |
| R4 / R7 | Sites or VPCs with overlapping private ranges | `10.1.2.3@A` to A's sensors, `10.1.2.3@B` to B's; results on different assets | Declared network per site |
| R5 / R9 | Split-horizon names; internal names with public addresses | Route the name to the network whose DNS suffix holds it, resolved by that network's sensor | Declared suffixes + scan vantage |
| R6 | VPN or peering to another site | The other site's own sensors first, the peered sensor as fallback | Declared reach + learned |
| R8 | Public range reachable only from inside | The site's sensors; the external view records "filtered from outside" | Declared zone + learned |
| R10 | Several sensors reach an asset | One sensor ranked by evidence, locality, health, load; or `vantage=both` with tagged results | Rank / scan setting |
| R11 | A sensor moves | Detected on its next report; private-network work held until an administrator confirms; evidence reset | Detected + confirm |
| R12 | New sensor | Detected at first start; one-click suggestion to join a zone; until then only what grant and detected facts allow | Detected + confirm |
| R13 | Platform-hosted sensor | Internet units only (already a hard rule) | Platform |
| R14 | Air-gapped site | Same routing, delivered as a signed offline job (research/119) | Declared |
| R15 | IPv6 | v6 units only to sensors with a v6 route; ULA treated like RFC 1918; link-local never | Detected |
| R16 | NAT / hairpin | A sensor whose egress address lies in the target's prefix scans as `internal` vantage | Detected (egress echo) |
| R17 | Web targets behind a forward proxy | Web units to sensors holding that egress profile (RFC-034) | Declared |
| R18 | Port-specific reach | Results per (vantage, port); a port filtered from one vantage never closes a port open from another | Learned |
| R19 | MSSP | Networks are per tenant; no cross-tenant interaction | Tenant data model |
| R21 | One sensor in two networks whose ranges overlap | Refused at assignment | Platform validation |

## 4. Design

### 4.1 Network self-description (sdk-go `pkg/netctx`)

A sensor built on `core.BaseSensor` / `sensorkit` gets this without tool code.

| Member | Source | Notes |
|---|---|---|
| `declared.site` | `SENSOR_NETWORK_SITE` or policy `network.site` | Label ≤ 64 characters; matched to a network by name only as a suggestion |
| `declared.reach[]` | `SENSOR_NETWORK_REACH` or policy `network.reach` | CIDRs the host owner says this host routes to (VPN, peering) |
| `declared.dns_suffixes[]` | `SENSOR_NETWORK_DNS_SUFFIXES` or policy `network.dns_suffixes` | Names this host resolves with its internal view |
| `declared.internet` | `SENSOR_INTERNET` = `auto` (default) \| `direct` \| `proxy` \| `none` | Host-owner override of detection |
| `detected.on_link[]` | Unicast interface prefixes (no loopback, link-local or container bridges), ≤ 32 | Private prefixes listed; public prefixes counted unless `report: full` |
| `detected.default_route` | v4 and v6 routing table (Linux `/proc/net/route`, `/proc/net/ipv6_route`; other systems: unknown) | |
| `detected.resolvers[]`, `search_domains[]` | `/etc/resolv.conf`, or `SENSOR_DNS_RESOLVERS` when set | |
| `detected.egress` | Egress echo against the platform (direct, then through the scan proxy when one is set) | `direct` \| `proxy` \| `none` \| `unknown` + the egress address the platform saw |
| `fingerprint` | SHA-256 over the sorted on-link private prefixes, default gateways, resolvers, search domains and site | Changes when the sensor moves; excludes the egress address (dynamic) |
| `report` | `SENSOR_NETWORK_REPORT` or policy `network.report` = `summary` (default) \| `full` \| `off` | `off` sends only the fingerprint and egress mode |

- **Effective report = declared ∩ local policy.** When the local policy has
  `targets.allow`, the report never names reach outside it and says how many
  entries were trimmed. Detection never changes local enforcement; the
  platform cannot widen the local policy.
- **Egress check failure is not "no internet".** In `auto`, an echo failure
  while the control channel works is `unknown`, not `none`: a blocked echo
  must not narrow a sensor that can reach the internet. `none` comes only
  from the host owner or from "no default route".
- **Sent** as the manifest's `network` member (RFC-033), only to a platform
  that lists the `network` feature on hello; covered by the manifest digest.
  Re-checked every 5 minutes; a change of the report changes the digest,
  which sends the manifest again. Key-bound sensors sign every request, so a
  report is attributable; a bearer sensor's report is accepted but can only
  narrow.
- **Bounds**: 32 on-link prefixes, 64 reach CIDRs, 32 suffixes, 8 resolvers,
  8 search domains. The platform re-validates as it does the rest of the
  manifest.
- **No side effects**: detection reads local tables and talks only to the
  platform; no cloud metadata endpoints, no LAN scanning.
- **Doctor checks**: `network.egress` (mode and why), `network.dns_view`
  (resolver configuration readable and consistent), `network.declared_vs_detected`
  (declared reach with no route from this host).

### 4.2 Per-target reach outcomes (sdk-go `pkg/reach`)

`reach.Classify(err)` maps an error toward a target to one class:

| Class | Path works? | Typical source |
|---|---|---|
| `reached` | yes | any response, TLS failure, reset after connect |
| `port_closed` | yes, the port is closed | `ECONNREFUSED` / `WSAECONNREFUSED` |
| `no_route` | no: no route from this sensor | `ENETUNREACH`, `EHOSTUNREACH`, "no route to host" |
| `firewall_refused` | no: a filter on the path refused this vantage | `EACCES` / `EPERM` on connect, ICMP administratively prohibited |
| `timeout` | ambiguous: filtered, down, or no path | `ETIMEDOUT`, i/o timeout, context deadline |
| `dns_failure` | no: the name does not resolve in this view | `*net.DNSError` (not found, server failure, timeout) |
| `unknown` | not a reach signal | anything else (canceled, not a network error) |

The table is tested for the error forms each operating system returns:
`syscall.Errno` values, `*net.OpError` / `*os.SyscallError` wrappers, IPv4 and
IPv6 addresses, Windows `WSAE*` codes, and DNS errors.

`reach.Recorder` collects outcomes during a job (safe for concurrent use);
`sensorkit` and the guarded dialer feed it, tool parsers add their own. It
produces the result metadata below. Only admitted job targets are recorded.

**Result metadata** (on the command result, next to `refused_targets` and
`coverage_gaps`):

```json
{
  "reach": {
    "v": 1,
    "targets": 12,
    "reached": 9,
    "unreached": 3,
    "classes": {"reached": 7, "port_closed": 2, "no_route": 1, "timeout": 2},
    "blocks": [
      {"block": "192.0.2.0/24", "port_class": "web", "reached": 4, "port_closed": 1, "timeout": 2},
      {"block": "2001:db8::/64", "port_class": "mgmt", "no_route": 1}
    ],
    "blocks_total": 2
  },
  "unreached_targets": [{"target": "192.0.2.7", "class": "timeout"}],
  "unreached_targets_total": 3
}
```

- A target counts once: its best outcome wins (`reached` > `port_closed` >
  `firewall_refused` > `no_route` > `dns_failure` > `timeout`), so a host
  that answered on one port is never "unreachable".
- `reached` counts targets whose path works (`reached` or `port_closed`).
- `port_class`: `web` (80, 443, 8000, 8008, 8080, 8443, 8888), `mgmt` (22, 23,
  135, 139, 445, 3389, 5900, 5985, 5986), `other`; `any` when no port is known.
- Bounds: ≤ 512 block rows (`blocks_total` keeps the full count), ≤ 100
  unreached targets (`unreached_targets_total` keeps the count), no
  per-address list for reached targets.

### 4.3 Polite reach probe (sdk-go `reach.Probe`)

A cheap test of whether this sensor reaches a job's targets, for the guided
install reach test (research/119 I1), liveness passes and the sensor's own
pre-checks:

- one TCP connect per (address, port), default ports 443, 80, 22; one
  attempt; 2 s timeout; no payload, no ICMP;
- at most 10 connects per second per probe, one connect per address at a
  time, at most 256 addresses per probe (the rest are reported as not probed);
- **only through the guarded dialer** (`core.LocalPolicy.AdmittedAddrs` /
  `DialContext`): job admission, local policy, built-in deny list and pinned
  addresses. A name resolves once through the guard and only its admitted
  addresses are dialled. An address the job did not admit is never touched.
- it is active work: tier T1, honours scan windows; a sensor exposes it as the
  `reach.probe` capability.
- the platform knows it as a sensor service: the tool `reach-probe` and the
  capability `reach.probe@1` are kept from a sensor's report and manifest
  without a tool catalog row (`sensorServiceTools`), so tenants never pick
  it as a scan tool and the platform can route probes to the sensors that
  serve it.

`conformance.RunReachSuite` proves, with a recording dialer: the probe never
dials an address outside the admitted set (IPv4 and IPv6, ranges, names that
resolve outside), the rate and size bounds hold, the classifier table, and
the summary stays bounded and deterministic.

### 4.4 Routing inside eligibility (api)

The eligibility function of research/119 E1 stays the single place that
decides. Per typed unit (RFC-088: `name`, `addr`, `range`, `url`):

1. **Network context.** `addr`/`range`: from the asset it was expanded from,
   the scope entry that admitted it, the scan's network selector for literal
   targets; a public address is internet; a private address in a tenant with
   one network is the default network; otherwise refuse `NETWORK_AMBIGUOUS`.
   `name`/`url`: a name under a network's DNS suffix belongs to that network
   and is **not** resolved on the platform (its network's sensor resolves and
   pins it); otherwise internet, resolved as today.
2. **Zones** of that network whose ranges hold the unit (narrowest wins, as
   today). Zones may overlap across networks, not within one.
3. **Authorized sensors** (hard, unchanged): tenant, trust, grant, zone
   membership, tool and confinement, local policy; plus the local policy's
   allowed ranges in the policy report, so a job outside `targets.allow` is
   never claimed only to be refused.
4. **Self-narrowing** (hard, only removes, only from a sensor that sent a
   report):

   | Reason | When |
   |---|---|
   | `sensor_no_internet` | internet unit, the sensor reports `internet=none` |
   | `sensor_internet_proxy_only` | internet unit, `internet=proxy`, the tool ignores proxies |
   | `sensor_no_ipv6` | v6 unit, no v6 route |
   | `sensor_declares_no_route` | private unit outside every declared and detected prefix |
   | `reach_changed_unconfirmed` | fingerprint changed, not confirmed, private unit (wait) |

   A sensor with no report is unknown and is not narrowed, so older sensors
   keep today's behaviour.
5. **Preferences** (order only, through RFC-030 D11 soft affinity): learned
   verdict, locality (home network before peered), vantage match, health,
   free slots.

Cheap predicates are claim columns stamped at plan time
(`commands.network_id`, `requires_internet`, `ip_family`, `vantage`); report
based ones run in the Go claim gate next to `Accepts`. A batch never mixes
networks.

**When no sensor can reach a unit** the unit is refused or waits, with a
reason and a fix; the rest of the run proceeds:

| Reason | Wait or refuse | Fix shown |
|---|---|---|
| `NETWORK_AMBIGUOUS` | refuse at trigger | choose the site |
| `NO_ZONE_COVERAGE` (exists) | refuse | create a zone or add the range |
| `NO_SENSOR_IN_ZONE` | refuse | install a sensor for that zone |
| `sensor_no_internet` (all candidates) | refuse when no tenant sensor has internet and the platform pool is off, else wait | enable platform scanning or install an external sensor |
| `sensor_internet_proxy_only` | refuse for raw-socket tools | direct egress needed |
| `sensor_declares_no_route` | refuse when every zone sensor declares none | add the route or change the zone |
| `reach_changed_unconfirmed` | wait | confirm the sensor's site |
| `learned_no_route`, `learned_blocked` | warning only | — |

### 4.5 Networks for overlapping space

RFC-023 D15, built here as `scan_networks`:

| Table | Change |
|---|---|
| `scan_networks` (new) | `id, tenant_id, name, kind (site\|cloud\|cluster\|other), description, dns_suffixes text[] ≤ 32, is_default`; unique `(tenant_id, name)`; ≤ 100 per tenant; internet is implicit (`network_id IS NULL`); composite FK `(tenant_id, id)` everywhere |
| `scan_zones` | `network_id NOT NULL`, backfilled to the tenant's default network for tenants with zones |
| `scan_zone_sensors` | a sensor may not serve zones of two networks whose ranges overlap |
| `scope_targets`, `scope_exclusions` | `network_id NULL` = every network of the tenant (today's meaning) |
| `assets` | `network_id NULL` = internet or default; identity becomes unique `(tenant_id, COALESCE(network_id, zero), name)` |
| `commands` | `network_id`, `vantage`, `requires_internet`, `ip_family` |
| ingest | assets from a command inherit its network; a result naming an address outside the command's network or units is dropped |
| `sensor_network_reports` (new) | `tenant_id, sensor_id, digest, fingerprint, report jsonb ≤ 16 KiB, received_at, signed`; `sensors.network_state (unknown\|detected\|confirmed\|changed)`, `sensors.home_network_id`; 10 versions kept |
| `sensor_reach_evidence` (new) | `tenant_id, sensor_id, network_id, block, port_class, counts per class, last_ok_at, last_fail_at`; 7-day half-life at read time, rows expire after 30 days, ≤ 10 000 rows per sensor |

Learned verdict per (sensor, block): `reaches` (any `reached`/`port_closed`),
`no_route` (a `no_route` with no success since), `blocked` (≥ 2
`firewall_refused`, no success), `dark` (only timeouts, ≥ 8 attempts across ≥ 4
addresses), `unknown`. "Host down" and "cannot route" are told apart per block:
when other addresses in the block answer from sensor X, a silent address is
down; when nothing answers from X but something answers from Y, it is X's
route. A fingerprint change clears the sensor's evidence.

### 4.6 Vantage

Scan setting `vantage`: `auto` (default: internet units to external sensors
when any is authorized, else internal sensors with internet egress, tagged
`internal`), `external` (private units refused `VANTAGE_EXTERNAL_PRIVATE`),
`internal`, `both` (units in a zone or under a network suffix get one external
and one internal unit). The platform stamps vantage on ingest reports, asset
services (`seen_external_at`, `seen_internal_at`) and findings. A scan can only
close what its own vantage observed: vantage is part of every future
staleness key.

### 4.7 Unreachable is not success

- A step whose result has `reach.targets > 0` and `reach.reached = 0` fails
  with **`TARGET_UNREACHABLE`** (class `placement`: the fix is routing, not a
  retry of the same work).
- A step with some unreached targets completes **partial**, with the count and
  a bounded summary (as refused targets and coverage gaps do).
- Older sensors send no reach summary; their failure text is matched
  (`network is unreachable`, `no route to host`, `host is unreachable`,
  `target unreachable`, …) to `TARGET_UNREACHABLE`.
- "No open ports" is shown only for units that answered.

## 5. Security

| Threat | Control |
|---|---|
| A sensor claims reach to **widen** its work | Reach never authorizes. Claim filters stay scope + grant + zone membership + local policy; a report can only remove the sensor from candidates or reorder authorized ones. Suggestions need `sensors:zones:write` and are audited. |
| A sensor **poisons evidence** | Evidence is per sensor and moves only that sensor's rank among authorized candidates; it cannot pull work from another zone or network. Dodging work is visible as a warning. |
| A sensor lies about its fingerprint | The hold defends honest moves; job signing and result binding (addresses outside the command's network or units dropped) bound a hostile sensor. |
| **Cross-tenant leak** through networks | Networks, reports and evidence are tenant-keyed with composite FKs; suggestions use the tenant's own sensors only; platform sensors redacted; the egress echo returns only the caller's own address. |
| Results written to **the wrong site** | Assets inherit the command's network; out-of-network addresses dropped; a moved sensor's private work held until confirmed. |
| **Probes touch out-of-scope addresses** | `reach.Probe` dials only through the guarded dialer and only admitted addresses; rate and size bounded; conformance test with a recording dialer. |
| **Detection side effects** | Local tables and the platform only; no metadata endpoints, no scanning. |
| **Internal topology disclosed** | `summary` by default (private prefixes, public counted), `off` honoured, report ⊆ local policy; reports are tenant data under the tenant's retention and erasure rules. |
| Egress echo abused | Authenticated sensor endpoint, rate-limited per sensor, returns only the peer address seen through `pkg/httpsec`. |
| Split-horizon names bypass scope | A name under a suffix still passes the scope gate as a name; its addresses are re-checked on the sensor (local policy) and against the network's zone ranges. |

## 6. Not built

- No automatic zone, network or membership creation: suggestions only.
- No traceroute, no LAN discovery during detection, no cloud metadata reads.
- No per-address evidence; no latency-based scheduling beyond rank.
- No label-based routing.
- `vantage=both` only for units in a zone or under a network suffix.

## 7. Plan and status

| Step | Repo | Content | Depends | Security-sensitive | Status |
|---|---|---|---|---|---|
| 1 | sdk-go | `pkg/reach`: classifier, recorder, result summary | — | — | In review (openctemio/sdk-go#260) |
| 2 | sdk-go | `pkg/netctx`: self-description, manifest `network` member, doctor checks | — | yes | In review (openctemio/sdk-go#262) |
| 3 | sdk-go | `reach.Probe` + `RunReachSuite` conformance | 1 | yes | In review (openctemio/sdk-go#261) |
| 4 | sensor | reach summaries from tool output, network report, `reach.probe` capability | 1–3 released | yes | Designed |
| 5 | api | store network reports, egress echo, self-narrowing at claim, policy report carries allowed ranges, eligibility reasons | E1 (research/119), 2 | yes | Designed |
| 6 | api | `TARGET_UNREACHABLE`, partial counts, text patterns for older sensors | — | — | Shipped (#1981) |
| 7 | api docs | this RFC | — | — | Draft (#1977) |
| 8 | api | networks (`scan_networks`, zone network, scope entries, command network, ambiguity, overlap check) | RFC-088 units | yes | Designed |
| 9 | api | network context in asset identity, ingest stamping, output binding | 8 | yes | Designed |
| 10 | api | learned reach evidence, verdicts, preferences | 4, 5, E1 | yes | Designed |
| 11 | api | vantage setting and stamping | 8 | yes | Designed |
| 12 | api | split-horizon names | 8, research/118 resolve-before-active | yes | Designed |
| 13 | api | network suggestions and move confirmation | 5 | yes | Designed |
| 14 | web | sensor Network tab, suggestions, move banner, networks in Scan zones | 5, 13 | — | Designed |
| 15 | web | routing preview by unit with vantage, run coverage line, exposure diff | 8, 11 | — | Designed |

Risks: step 9 touches every asset upsert path (NULL keeps today's identity;
rehearse on a restored backup); self-narrowing false negatives (an echo
failure is `unknown`, not `none`); step 6 changes what users see (steps that
read "completed, 0 results" become partial or failed).
