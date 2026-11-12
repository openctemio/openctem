# RFC-088: Scope-aware target allocation

| | |
|---|---|
| Status | Accepted (2026-10-13); steps 1–8 implemented, steps 9–14 planned |
| Scope | api (target gate, `pkg/domain/scope/ipset`, stage literal gate, workflow chunking, command host keys), later sdk-go + sensor (range iterator, job exclusions, `discover.hosts`), web (preview funnel, knobs) |
| Architecture | [active-probe-gate.md](../architecture/active-probe-gate.md), [scan-targets.md](../architecture/scan-targets.md), [scan-stages.md](../architecture/scan-stages.md) |
| Related | RFC-030 (scan distribution: pull, chunks, leases, fair share), RFC-040 (mutual distrust sensor/platform), RFC-054 (scope model, deny list, tiers), RFC-068 (dynamic target selectors), RFC-082 (network seeds), research/118 |

## 1. Summary

A scan's targets are what a person typed (`*.example.com`, `203.0.113.0/24`,
`app.example.com`), what selectors expand to and what earlier stages found.
How that work is cut up and handed to each stage decides what is scanned,
how fast, and whether anything outside scope is touched.

Names are handled well since RFC-068: a wildcard expands to the apex plus
inventory names, discovery gets the apex only, and discovered names pass the
per-hop gate. **Address ranges were one opaque string end to end**:

- an exclusion that overlapped a range dropped the whole range (a /16 with
  one excluded address was not scanned at all), on the platform and again on
  the sensor;
- a typed range went to **every** stage of a workflow, HTTP probing and
  vulnerability templates included (only asset-group members were
  type-gated);
- chunking counted strings, so a /16 was one chunk on one sensor;
- politeness host keys treated a range as its own key, so a range chunk and
  an address chunk inside it could run at the same time from two sensors.

This RFC makes the platform planner the authority on *what* each stage
receives: exact address-set arithmetic, typed work units, weight-based
chunks and overlap-aware politeness. Later steps add liveness-first scanning
of ranges, resolve-before-active for names and sensor-side re-checks.

## 2. Invariants

1. **Nothing outside scope is ever sent.** Every unit sent to a sensor is a
   subset of (target) minus (active exclusions) minus (the built-in deny
   list). Computed on the platform with exact interval arithmetic,
   re-checked on the sensor, and results outside the unit are dropped at
   ingest (a scan command given only addresses and ranges: any reported
   asset that names only other addresses).
2. **Exclusions win at the finest grain.** A range is cut around an
   exclusion: never dropped whole, never scanned through.
3. **The deny list is always on**, on both sides.
4. **Names never authorize addresses** (RFC-054 S4, unchanged).
5. **Bounded everywhere.** A range is a descriptor (an interval), never an
   address list in memory; one range target is at most 2^16 addresses; one
   dispatch cuts its ranges into at most 4 096 pieces.
6. **Fail closed.** A lookup or arithmetic step that cannot complete refuses
   the work with a reason; it never widens and never silently narrows.
7. **Mutual distrust (RFC-040).** The platform plans; the sensor verifies
   every unit against its local policy.

## 3. Work units

| Unit | Example | Weight | Host keys |
|---|---|---|---|
| `name` | `api.example.com` | 1 | the name |
| `addr` | `203.0.113.7` | 1 | the address, plus a bucket marker for its /24 (IPv4) or /120 (IPv6) |
| `range` | `203.0.113.0/25` (a piece) | its address count | one bucket key per covering /24 or /120 |
| `url` | `https://app.example.com/` | 1 | its host |
| `service` | `203.0.113.7:8443` | 1 | its host |

A literal target is classified by its text; an inventory target keeps its
stored type. `scan_run_targets` holds one row per piece, never per address.

## 4. Address-set arithmetic (step 2)

`pkg/domain/scope/ipset` stores a set as sorted, disjoint, inclusive address
intervals (IPv4 and IPv6 apart; an IPv4-mapped address is IPv4). It offers
union, intersection, subtraction, address count (saturating for IPv6) and the
minimal prefix cover, optionally cut so no prefix is wider than a bound, with
a piece limit. No operation lists addresses.

The scan target gate (`ResolveDispatchTargets` with `SplitRanges`, set by
the scan trigger and `POST /scan-workflows/runs`) replaces each range
target with:

```
pieces = prefixes( target − active address/range/CIDR exclusions − deny list )
```

- nothing removed: the target is kept as written;
- something removed: the pieces are dispatched instead and the run's
  warnings name the range and how many addresses were left out;
- nothing left: excluded (refused `deny_list` when only the deny list
  removed it);
- a range wider than 2^16 addresses: refused on every path, including the
  ones that skip the scan target validator;
- more than 4 096 pieces in one dispatch: `RANGE_TOO_FRAGMENTED` (merge
  scattered exclusions).

Each piece then passes every other gate check on its own (the whole-target
exclusion match as defence in depth, ownership with the range asset's entry,
act scope, tier, zones). A range target that also matches by other names
(an inventory asset's alternative names) keeps the whole-target rule. Paths
that map the gate's answer back onto their own list (coverage, validation,
connectors, the claim-time re-check, the dry run) keep the whole-target rule
until they learn about pieces.

**Sensor side.** The sensor's local policy still refuses a range that
overlaps its own deny list or `targets.deny` whole. Pieces from the platform
never overlap the built-in deny list; an operator's local `targets.deny`
overlapping a piece refuses that piece (fail safe). Since step 7 the job
carries the tenant's exclusions inside the /24 (IPv6 /120) buckets of its
ranges (payload `exclusions`, covered by the job signature), and the SDK
walks each range address by address, leaving out what the job's
exclusions, `targets.deny` or the built-in deny list covers.

## 5. Each stage gets only the kinds it accepts (step 3)

The step's catalogue stage declares its inputs. Every target of a step,
typed or literal, is classified (`name`, `addr`, `range`, `url`, `service`)
and kept only when the stage accepts that kind:

| Stage | name | addr | range | url | service |
|---|---|---|---|---|---|
| `discover.subdomains`, `lookup.rdap` | yes | – | – | – | – |
| `resolve.dns` | yes | – | – | – | – |
| `lookup.asn` | – | yes | yes | – | – |
| `scan.ports` | yes | yes | yes (until liveness ships) | – | yes |
| `probe.http` | yes | yes | **no** | yes | yes |
| `crawl.web`, `dast.web` | – | – | – | yes | – |
| `vuln.templates` | yes | yes | **no** | yes | yes |

A sixth kind, `path`, is a host and a path without a scheme: the form of a
repository (`github.com/acme/app`, `git@github.com:acme/app`) or an image
reference. No stage in the table takes it, whatever its stored type, and a
repository asset counts as a `path` whatever its name: a network tool given
one would probe the code host, which many organizations share. A web path is
written as a URL with its scheme. See "Repositories and path targets" in
`docs/architecture/active-probe-gate.md`.

Stages outside the network kinds (code, containers, cloud) are not gated
here. A single-scanner scan applies the same rule for the scanner's stage. A
step left with nothing fails with `INCOMPATIBLE_TARGETS`, as before; a
chained step may still take its predecessors' outputs.

## 6. Pieces, weight chunks and overlap-aware politeness (step 4)

- **Pieces of at most /24 (IPv4) or /120 (IPv6).** The gate cuts every range
  target into such pieces (a /16 is 256), inside the 4 096-piece bound.
- **Chunks by address count.** A workflow step's chunk holds at most the
  capability's target count *and* at most its address budget (`scan.ports`
  1 024 addresses); a passive stage (`lookup.asn`) weighs every target 1.
  A /16 port scan is 64 chunks that every eligible sensor shares.
- **Politeness knows about overlap.** A chunk's host keys hold, for each
  address, the address and an `in:` bucket marker; for each range piece, a
  `net:` bucket key. A pending command is held back while an acknowledged
  or running command of the tenant holds a key it conflicts with: equal
  keys, an address whose bucket another chunk scans as a range, or a range
  whose bucket holds another chunk's address. Two addresses in one bucket do
  not conflict. Claims lock one advisory lock per bucket, so two claims of a
  range and an address inside it are serialised.

## 7. Host discovery (step 5)

`discover.hosts@1` (ctis taxonomy; discover.active, T1) takes addresses and
ranges and reports each live address as an `ip_address` with the probe that
answered (`properties.live_by`, for example `tcp:443`). The platform stage
`discover.hosts` takes `ip_address` and `network`, emits `ip_address`, and is
the `cidr → ip` adapter. Its chunks hold at most 64 targets and 4 096
addresses (a /16 liveness pass is 16 chunks).

naabu implements it next to `scan.ports`, by capability only: the sensor runs
naabu as a TCP connect probe of a few ports (80, 443, 22, 3389, 8080, 8443
unless the step names others) and keeps only the answering addresses. The
tool sandbox grants no raw sockets, so ICMP is not used. A step that pins
naabu without naming the capability stays a port scan, and a naabu report
that names no capability is bound to `scan.ports`. A step that names
`discover.hosts` requires the capability, so only sensors whose naabu
implements it claim it.

### Live hosts first (step 6)

`target_options.cidr_mode` gains `liveness`, the default of a new scan with
a range when its scan can run it (a single scanner, or a workflow with a
Host discovery step); a workflow without one keeps sweeping, and an
explicit `liveness` there is refused. A scan saved before keeps sweeping,
also when it is edited, until a person chooses live hosts first (decision
A1); the console suggests it where the scan can run it. In a liveness run the range pieces go to
Host discovery and passive lookups only; every other active step gets the
live hosts Host discovery found plus the inventory's addresses inside the
ranges. The platform sends the probe ports with every host discovery job.
The Network starter workflow now starts with Host discovery. Details:
[scan-targets.md](../architecture/scan-targets.md).

## 8. Wildcard DNS (step 8)

A zone with a wildcard record answers for any name under it, so passive
sources, permutations and guesses all "resolve". Two layers keep such names
from being treated as the tenant's hosts:

- **Sensor (first layer).** dnsx runs with `-auto-wildcard` by default
  (sensor #234; `dnsx.NewScanner`, `RespectWildcard`): a name that resolves only
  through a wildcard record of its zone is not reported. The platform also
  sends `wildcard_filter: true` with every dnsx job that does not set it
  (`withWildcardFilter`), so an older sensor or a sensor with another
  default filters the same way.
- **Platform (second layer).** A finished filtered resolution marks the
  names it was given and did not report (`asset_wildcard_dns`); the
  active-probe gate refuses a marked name, and a service or URL on it, as
  `wildcard_only` (passive only) until a person confirms it or a filtered
  resolution reports it; the scope join never confirms it; and active
  stages take a name only with recent resolution evidence (A5).

The sensor-side filter stays on as defence in depth; the two layers back
each other up. The sensor filter keeps wildcard answers out of the inventory
at the source, so a wildcard-only name never gains DNS evidence. The
platform marks hold for a name that reached the inventory by another path (a
passive source, an earlier unfiltered run, auto-confirmation before it was
resolved) and decide at the gate, so a scope entry over a wildcard zone does
not make its guessed names scannable. A step that sets `wildcard_filter:
false` turns the filter off for that job on purpose: its resolution changes
no mark either way. Architecture:
[scan-targets.md](../architecture/scan-targets.md#resolve-before-active),
[active-probe-gate.md](../architecture/active-probe-gate.md).

## 9. Steps

Steps 1–4 are described in §3–§6, steps 5 and 6 in §7, step 8 in §8.

| # | Step | Security-sensitive | Status |
|---|---|---|---|
| 5 | `discover.hosts` capability (light ICMP/TCP liveness, naabu host discovery) across ctis, sdk-go, sensor and api (§7) | – | implemented |
| 6 | Liveness-first `cidr_mode` (default for new scans): liveness, then deep stages on live plus known addresses; `sweep` only up to /24 | – | implemented |
| 7 | Exclusions in the signed job; SDK range iterator skips them and the deny list per address; naabu `-exclude-hosts`; ingest drops results outside the chunk's units | yes | implemented |
| 8 | Wildcard-DNS detection on by default; active stages skip names that do not resolve or resolve only through a wildcard (§8) | yes | implemented |
| 9 | Bounded recursive discovery of sub-zones (depth 2, max 3; budgets 5 000 per root, 10 000 per run) | – | planned |
| 10 | Name grant vs address grant for port scans (names without an address entry: web ports only; shared edges never fully scanned) | yes | planned |
| 11 | Single-scanner list tools chunked like workflow steps | – | planned |
| 12 | Coverage rotation (least recently scanned first) and deep-stage freshness | – | planned |
| 13 | Web: "What will be scanned" funnel and run funnel | – | planned |
| 14 | Tenant knobs and platform ceilings | – | planned |

Since step 7 a platform sensor's claim (`get_next_platform_job`) honours the
same host keys and bucket locks as a tenant sensor's.

## 10. Decisions

| # | Question | Decision |
|---|---|---|
| A1 | Default for a range in a new scan | liveness first (step 6); an existing scan keeps its mode on edit and is never switched silently: the edit form and the scan detail page suggest "Live hosts first (recommended)" with a one-click switch where the scan can run it |
| A2 | Exclusion inside a range | cut the range (exact subtraction); never drop, never scan through |
| A3 | Discovery depth | 2 levels below the root by default, max 3, budgets 5 000 per root and 10 000 per run |
| A4 | Wildcard-DNS filter | on by default; names that resolve only through a wildcard are never active units and never auto-confirmed. Step 8: the platform sends `wildcard_filter: true` with every dnsx job that does not set it, so such names never gain resolution evidence. A finished filtered job marks the names it was given and did not report (`asset_wildcard_dns`); the active-probe gate refuses a marked name as `wildcard_only` (passive only) until a person confirms it or a filtered job reports it, and the scope join never confirms it |
| A5 | Names that no longer resolve | skipped by active stages (`not_resolving`, 7-day freshness). Step 8: decided by the platform from the freshest evidence it holds (asset freshness classes dns, http, tls, ports); a name without any evidence is handed on and the sensor resolves it; a skipped name's enrichment is requested again ([scan-targets.md](../architecture/scan-targets.md#resolve-before-active)) |
| A6 | Port scan of a name without an address entry | web ports only; shared edges never fully scanned |
| A7 | Where expansion lives | the platform planner is the authority; the sensor re-checks every unit and address; ingest drops out-of-unit results |
| A8 | Over-cap selection | rotation by least recently scanned, not freshest |

## 11. Threat model

| Threat | Control |
|---|---|
| Excluded addresses scanned through a range | exact interval subtraction, property-tested against brute force; pieces carry no excluded address and are matched again by the whole-target rule; the sensor's policy re-checks every piece (per address from step 7) |
| Platform DoS by a huge range | ranges stay intervals; 2^16 addresses per range target, 4 096 pieces per dispatch, chunk budgets |
| A range reaching HTTP probing or templates (volume, third-party noise) | the stage kind gate on every step, typed or literal |
| Two sensors on one network at once | overlap-aware host keys and per-bucket claim locks |
| Cross-tenant effect | exclusions, host keys and claims are read per tenant; another tenant's exclusion never cuts a range and another tenant's chunk never holds one back |
| Splitting bypasses ownership | pieces inherit the range asset's entry and are gated by its id |
| Restricted member widens reach via pieces | pieces are subsets of a target the act scope already admitted, and each piece is checked again |

## 12. Non-goals

- No ASN scan target (RFC-082 D6 stands).
- No platform-side reverse-DNS sweep and no IPv6 sweeps wider than /112.
- No address inheritance from names (RFC-054 S4).
- No second target list: units are derived from the scan's targets and
  selectors at run time.
