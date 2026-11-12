# RFC-075: Asset freshness and automatic enrichment

| | |
|---|---|
| Status | Proposed (2026-10-11); P0 in implementation |
| Scope | api (`pkg/domain/assetfreshness`, `internal/app/assetfreshness`, ingest observation hook, enrichment controller, the EASM settings section, two migrations), web (asset detail freshness panel, inventory filter, switch on the attack-surface monitoring card) |
| Architecture | [asset-freshness.md](../architecture/asset-freshness.md) |
| Related | RFC-019 (certificate transparency), RFC-036 (EASM candidates, O4 auto-confirm), RFC-039 (continuous retest), RFC-046 (Scan → Run → Task, stage catalogue, hop router), RFC-054 (scope model), RFC-065 (bug bounty programs), RFC-067 (scan windows), RFC-068 (dynamic scan targets), RFC-069 (attribute reconciliation, change timeline), RFC-071 (scan intensity), RFC-073 (scan approval governance) |

## 1. Summary

An asset found by any source is enriched at once, passively, and its
enrichable data is kept fresh afterwards, so the inventory never holds an
asset whose information quietly dies.

- Every enrichable **attribute class** (DNS, registration, network owner,
  HTTP, TLS, ports, …) of an asset carries `observed_at` and the source that
  observed it. Each class has a **freshness TTL**, shortened for critical and
  internet-facing assets. Per class and per asset the state is **live**,
  **stale** (past its TTL), **dead** (past three TTLs) or **never** (an
  applicable class nobody observed).
- **Triggers:** (a) a new asset from any source gets the built-in passive
  enrichment profile of its type, debounced and batched; (b) a staleness
  controller re-enriches the stalest, most important assets first within a
  per-tenant daily budget; (c) change-triggered chains (new address → network
  owner; DNS change → HTTP re-probe; new port → service fingerprint, only when
  intensity allows).
- **Jobs are ordinary scan runs** of built-in system workflows through the
  existing planner (capability → tool), dispatch gate, scan windows and
  governance. There is no second scanning engine.
- **Gates:** passive work only for names the tenant's scope covers; active
  work only when the tenant opted in for chosen labels and the scan gates
  allow it; unconfirmed EASM candidates and bug-bounty program targets stay
  passive and program rules apply at delivery as for every command.

P0 ships the smallest slice that keeps new assets alive: new asset (any
source) → built-in passive profile within minutes; per-class `observed_at`
recorded from every report; the freshness panel and a **stale** inventory
filter; one tenant switch, on by default.

## 2. Current state (develop e7c4a17b8, verified)

| Piece | Where | What it does today | Gap for freshness |
|---|---|---|---|
| `asset_discovered` trigger | `internal/app/automation/event_dispatcher_discovery.go:46`, wired in `cmd/server/services.go:2454` | Fires once per ingest batch for assets the ingest newly inserted (report assets, derived root domains and addresses); a workflow may `trigger_scan` | No default workflow, so nothing happens unless a person built one. Manual create (`AssetService.CreateAsset`, `internal/app/asset/service.go:360`) and CSV import (`internal/app/asset/import.go:40`) do not go through ingest and never fire it |
| Hop router | `internal/app/scanrun/hop_router.go`, [scan-stages.md §3](../architecture/scan-stages.md) | Inside one run, feeds names a stage found to later stages, hop ≤ 3, gate per tier (T0 `PassiveOnly`, T1 `ActiveGate`, T2 never chained) | Ends with the run. An asset found by run A is not enriched by anything once A ends |
| Dynamic scan targets | RFC-068 §5.4 | A scheduled run re-reads the inventory, so names found since the last run are scanned | Only on the schedule the tenant configured, and only for tenants that configured one |
| Continuous discovery preset | RFC-071 §7 | Two scans: Passive discovery of roots daily; Probe new assets of `*.<root>` daily with `new_since_last_run` | Daily, opt-in per root, active half needs a person to save it; nothing records whether an attribute is current |
| Certificate transparency | RFC-019, [certificate-transparency-monitoring.md](../architecture/certificate-transparency-monitoring.md) | At most `CERT_MONITOR_MAX_DOMAINS_PER_RUN` (default 50) watched domains queried per tenant per run, oldest first; exact names promoted to `subdomain` assets through ingest, at most 500 per run | The "results are not assets" gap is closed: promoted names are assets and fire `asset_discovered`. They are not enriched |
| EASM candidates | RFC-036, O4 | Auto-confirm only at confidence ≥ 90 with a strong rule; the rest go to review | Unconfirmed names may be resolved passively (T0 `PassiveOnly` refuses only rejected names); nothing does it automatically |
| Continuous retest | RFC-039 | Retests fixed findings on a cadence, reopens regressions | Covers findings, not asset attributes |
| Scan windows | RFC-067 | Every command waits for an open window of every source (organization, program testing windows) | Applies unchanged to enrichment runs |
| Attribute reconciliation | RFC-069 §11–§13 | `asset_attribute_sources` (four business attributes, per-source `observed_at`); `asset_attribute_set_elements` (IP addresses, technologies, open ports per source with `last_seen`); `asset_change_events` timeline; class TTLs decide which source wins | TTLs decide precedence, not "is this data still current"; DNS records, registration, network owner, HTTP title, TLS are stored in `properties` with no observation time |
| Scan intensity | RFC-071 | Every scan carries passive / active / intrusive; passive = in scope and off-target (`refusePassiveOutOfScope`, `internal/app/scan/dispatch_gate.go`) | Gives exactly the passive ceiling enrichment needs |
| Scan approval | RFC-073 | Approvals are opt-in governance; passive scans never need one | An active enrichment follows the tenant's governance like any scan |
| Passive lookups | migration `001967_passive_lookup_tools`, sensor tools `rdap`, `asn`, `dnsx` | `lookup.rdap` (registrar, dates), `lookup.asn` (origin AS, holder, prefixes), `resolve.dns` through recursive resolvers; all T0 | Run only inside a Passive discovery scan |
| Asset lifecycle | `internal/app/asset/lifecycle_worker.go`, `internal/infra/controller/asset_lifecycle.go` | Daily: active → stale when no scan saw the asset within the tenant's threshold | Demotes on silence; never asks a passive source first |
| Program targets | RFC-065, `internal/app/programtarget/ingester.go` | Program scope items become assets through ingest; rules (headers, user agent, rate, testing windows) applied at command delivery for every path | Applies unchanged to enrichment runs |

## 3. Goals and non-goals

Goals:

1. A new asset from any source is passively enriched within minutes, with no
   configuration.
2. Each enrichable attribute class of an asset shows when it was last
   observed and by whom, and whether it is live, stale or dead.
3. Stale data is refreshed in priority order (risk × staleness) within a
   budget the platform and the tenant control.
4. A change in one class triggers only the follow-up that change makes
   relevant, never a full re-scan.
5. Nothing reaches a third party that a person-started scan could not reach:
   enrichment passes every gate a scan passes, and passive is the default.

Non-goals: a second scan engine or job queue; enrichment from paid
third-party data services; intrusive (T2) enrichment (never automatic);
automatic confirmation of candidates (O4 stays the only rule).

## 4. Options considered

| Option | For | Against | Decision |
|---|---|---|---|
| A. Ship a default `asset_discovered` automation workflow per tenant | Reuses automations | Automations are tenant-editable objects: a deleted or edited default silently stops enrichment; no budget, no freshness model; does not cover manual or CSV assets | No |
| B. Enrichment as its own engine calling lookup services from the API | Fast | A second engine beside the planner, gates and sensors; platform egress to arbitrary names; tools duplicated | No |
| C. A platform enrichment controller that plans **ordinary scan runs** of built-in passive workflows, fed by an enrichment request table, with freshness recorded from every report | One planner, one gate, scan windows and governance apply; any source of data refreshes the clock | Ad-hoc runs appear in the runs list (tagged, filterable) | **Yes** |

## 5. Model

### 5.1 Attribute classes

A class groups attributes one stage observes together. P0 records the first
six from every report; later classes are added as rows in the class table
(code), not schema changes.

| Class | Observed by (stage) | Applies to | Attributes | Base TTL | Tier to refresh |
|---|---|---|---|---|---|
| `dns` | `resolve.dns` | domain, subdomain | A/AAAA/CNAME/NS/MX, `resolves_to` | 24 h | T0 |
| `registration` | `lookup.rdap` | domain | registrar, registrant org, name servers, `registered_at`, `expires_at` | 7 d | T0 |
| `network_owner` | `lookup.asn` | ip_address, network | ASN, holder, country, announced prefixes | 7 d | T0 |
| `http` | `probe.http` | http_service, website, subdomain, ip_address | status, title, server, technologies | 3 d | T1 |
| `tls` | `probe.http` | certificate | subject, issuer, SANs, `not_after` | 3 d | T1 |
| `ports` | `scan.ports` | ip_address, host | open ports (RFC-069 §13 set elements) | 7 d | T1 |
| `web_endpoints` (P2) | `crawl.web` | http_service, website | discovered URLs | 14 d | T1 |
| `code_deps` (P2) | `sca.deps` | repository | dependencies | 7 d | T0 |
| `screenshot` (P2) | a screenshot capability when the catalogue has one | http_service | image | 14 d | T1 |

`observed_at` is the report's observation time (`reportObservedAt`, never in
the future), recorded per (asset, class) with the tool name, whenever an
ingest **writes** the asset (creates or updates it) from a report whose tool
implements the class's stage and the asset's type applies. Any source counts:
a person's scan, a scheduled scan, an enrichment run, a CI run. A report
that refused or skipped the asset records nothing.

### 5.2 TTL and state

`ttl = base × factor`, factor 0.5 when the asset is `critical` or `high` or
internet-facing, else 1 (P0). P1 adds a change-rate factor: a class whose
value changed in the last 30 days (RFC-069 timeline events) gets 0.5, one
unchanged for 180 days gets 2. The TTL floor is 6 h, the ceiling 30 d.

| State | Rule |
|---|---|
| `live` | observed within `ttl` |
| `stale` | observed, older than `ttl` |
| `dead` | observed, older than `3 × ttl`: no live source; the value is shown dimmed |
| `never` | the class applies to the asset type and is passive (T0), and nothing observed it |

The asset's state is its worst class among those observed or applicable at
T0 (an active class nobody observed is not `never`: active is opt-in).

### 5.3 Tables

```
asset_attribute_freshness                 -- migration asset_freshness
  tenant_id, asset_id   FK (tenant_id, asset_id) -> assets, cascade
  class                 CHECK in the class list
  observed_at           report observation time
  source                tool name (<= 100)
  updated_at
  PK (tenant_id, asset_id, class)
  index (tenant_id, class, observed_at)   -- staleness picker, stale filter

asset_enrichment_requests
  tenant_id, asset_id   FK, cascade
  reason                new_asset | stale | change | manual
  requested_at          last request (debounce key)
  dispatched_at         last dispatch, NULL = pending
  attempts, last_run_id
  PK (tenant_id, asset_id)
  partial index (tenant_id, requested_at) WHERE pending
```

A row is upserted, never duplicated: a request for an asset that is already
pending keeps one row (idempotency key = tenant, asset). Rows cascade with
the asset and the tenant (organization deletion erases them) and move with
the asset in a merge.

### 5.4 Built-in profiles

System workflows (read-only, `tenant_id` = system, tagged `enrichment`),
built only from capability steps, so any active implementation runs them:

| Profile | Asset types | Steps (all T0) |
|---|---|---|
| Enrich root domains | domain | `resolve.dns`, `lookup.rdap` |
| Enrich host names | subdomain | `resolve.dns` |
| Enrich addresses | ip_address | `lookup.asn` |

Addresses a DNS resolution finds are new assets: they fire a new-asset
request and get their network owner in the next batch. The chain ends by
construction: only in-scope names are enriched, a resolver creates no names
except CNAME targets, and an out-of-scope CNAME target is refused at the
passive gate.

Active profiles (P1, opt-in): **Probe web** (`probe.http`), **Ports**
(`scan.ports` → `probe.http`), **Endpoints** (`crawl.web`, P2).

## 6. Triggers

### 6.1 New asset (P0)

Every creation path enqueues a `new_asset` request: ingest (scans, sensor
reports, CTIS uploads, finding imports, connectors, program targets,
certificate transparency, CI runs), manual create and CSV import. The
request is a row, written in the creating request's path (ingest's
discovered callback; the asset service after create; the import after the
batch); enqueueing never fails the creation (logged and counted).

The **enrichment controller** (every 2 min, every replica; claims with
`FOR UPDATE SKIP LOCKED`, so two replicas never dispatch the same row):

1. Per tenant with pending rows older than the 60 s debounce (or ≥ 200
   pending): skip if the tenant turned automatic enrichment off (rows are
   marked dispatched with no run, so they do not pile up).
2. Claim up to 500 pending rows, oldest first, within the daily budget
   (default 2 000 assets per tenant per 24 h, `ASSET_ENRICHMENT_DAILY_BUDGET`);
   the rest wait for the next tick.
3. Load the assets (tenant-scoped), drop archived, deleted and types without
   a profile, group by profile.
4. Per profile, start one **passive** run through the scan service with the
   names as targets, tagged `auto-enrichment`, triggered by the system.

### 6.2 Staleness (P1)

The same controller, once an hour, requests re-enrichment of the assets
whose passive classes are `stale` or `never`, ordered by
`priority = risk_weight × staleness`, where `staleness = age / ttl` and
`risk_weight` is 4 critical, 3 high, 2 medium, 1 otherwise, ×2
internet-facing. The budget is shared with new assets; new assets go first.
Fair share across tenants: each tick takes at most `budget / 24` per tenant,
so one large tenant cannot starve the others.

### 6.3 Change chains (P1–P2)

Driven by RFC-069 timeline events and set-element changes, each producing a
`change` request for one profile only:

| Change | Follow-up | Tier |
|---|---|---|
| DNS answer changed (new address, CNAME target) | `probe.http` of the name (P1, active opt-in) and `lookup.asn` of a new address (P0 via new asset) | T1 / T0 |
| New address | `lookup.asn` | T0 |
| New open port | service fingerprint (`probe.http` on that port) and then targeted `vuln.templates` only if the tenant's enrichment intensity is active and the label allows it | T1 |
| Certificate renewed or `not_after` < 14 d | re-probe `tls` | T1 |
| Registration `expires_at` < 30 d | re-run `lookup.rdap`, notify | T0 |
| Asset reappears (stale → active) | full passive profile | T0 |
| Asset not seen within the lifecycle threshold | passive verification (`resolve.dns`) before the lifecycle worker marks it stale or disappeared; an answer keeps it active | T0 |

## 7. Gates

| Gate | Rule | Where |
|---|---|---|
| Scope | Passive runs refuse every internet name or address no scope authority of the tenant covers (`refusePassiveOutOfScope`); the act scope is the system actor (scope entries only, no member data scope) | dispatch gate, unchanged |
| Validation | Internal, metadata and link-local targets refused | `validateScanTargets`, unchanged |
| Candidates | Unconfirmed EASM candidates and `needs_review` names: passive only, rejected names never | T0 `PassiveOnly` gate; active profiles use `easm.ActiveGate` |
| Bug-bounty targets | Passive only unless the tenant opts the program's label in; program rules (headers, user agent, rate, testing windows) applied at delivery | RFC-065 §12, unchanged |
| Scan windows | Enrichment commands wait for an open window like any command | RFC-067, unchanged |
| Governance | Passive needs no approval; an active profile follows RFC-073 (an approval policy that matches makes the run wait) | RFC-073, unchanged |
| Platform sensors | Active enrichment on platform sensors needs the targets proven when the platform sensor proof setting is on | RFC-054 §8.1, unchanged |
| Tenant switch | "Automatic enrichment": passive **on** by default; active **off**, opt-in per asset label (P1) | EASM settings section |
| Loop prevention | One request row per asset (idempotent upsert); 6 h cooldown per asset between dispatches unless the reason is `manual`; hop depth inside a run (≤ 3, unchanged); a change request is dropped when a run of the same profile for the asset is already planned or running | controller |
| Budget | Per-tenant daily asset budget, per-run cap 500, per-tick fair share; the run-level concurrency limits (3 per scan, 50 per tenant) unchanged | controller, scan service |

## 8. Use cases

| # | Trigger | Action | Gate | Expected data |
|---|---|---|---|---|
| 1 | New subdomain from certificate transparency | Enrich host names: `resolve.dns` | Passive, name under a scope root | addresses (new address assets, then network owner), CNAME; `dns` live |
| 2 | Subdomain whose address moved to a new hosting provider | DNS change → `lookup.asn` of the new address (P0 via new asset); timeline event on the subdomain | Passive | new `network_owner` holder; a `resolves_to` change on the RFC-069 timeline |
| 3 | New address inside an owned CIDR (scan or connector) | Enrich addresses: `lookup.asn` | Passive; address covered by a scope entry | origin AS, holder, prefix |
| 4 | New open port on an address | Service fingerprint `probe.http` on the port; targeted `vuln.templates` only for active opt-in labels (P2) | Active opt-in, governance, window | http service, technologies; findings |
| 5 | New web application (http_service) | `crawl.web` endpoint discovery (P2) | Active opt-in, label | discovered URLs |
| 6 | New repository from a code host connector | `sca.deps` (P2, T0: code analysis, no target traffic) | Repository belongs to the tenant's connector | dependencies, findings |
| 7 | CSV import of 2 000 host names | `new_asset` requests for each; batched into runs of ≤ 500 within the daily budget | Passive, scope | `dns` for each in-scope name; out-of-scope names refused and counted on the run |
| 8 | Cloud connector instance with a public address | Enrich addresses; ports and HTTP only on active opt-in | Connector source = strong rule; scope | network owner; later ports, http |
| 9 | Bug-bounty program target added | Enrich root domains / host names, passive | Program rules at delivery; passive unless opted in | `dns`, `registration` |
| 10 | Root domain of an acquired company matched by registration organization | Stays a candidate; passive `lookup.rdap` and `resolve.dns` only | `needs_review`: passive allowed, never active; O4 decides confirmation | registration data for the reviewer |
| 11 | Certificate expiring (< 14 d) | Re-probe `tls` (P1, active opt-in) and notify | Active opt-in | new `not_after` or an expiry finding |
| 12 | Domain registration expiring (< 30 d) | Re-run `lookup.rdap`, notify (P1) | Passive | new `expires_at` |
| 13 | Asset reappears after being stale | Full passive profile (P1) | Passive | all T0 classes live again |
| 14 | Asset not seen within the lifecycle threshold | Passive `resolve.dns` before the worker demotes it (P1) | Passive | an answer keeps it active; NXDOMAIN lets the worker demote it |
| 15 | Dangling DNS / takeover-prone CNAME | `dns` change of a CNAME target → the EASM DNS-only checks re-check that name now, not at the next daily pass (P1) | Passive | `dangling_cname` exposure |
| 16 | Asset owner or business unit changed | No traffic; priority of the staleness picker changes with criticality (P1) | None | next refresh sooner or later |
| 17 | Finding fixed | RFC-039 continuous retest (unchanged); a fixed finding on a `stale` asset first refreshes its passive classes so the retest targets the current address | RFC-039 gates | retest result |
| 18 | Manual "Refresh now" on the asset page | `manual` request, skips the cooldown, passive profile; active profiles if opted in (P1) | `assets:write` and data scope of the person | all classes of the profile |
| 19 | Scheduled discovery finds 300 new names in one run | One request per name, one batch of runs after the debounce | Passive | `dns` for each |
| 20 | Sensor report of an existing asset (any scan) | No request; `observed_at` of the classes the report's tool covers moves | None | the asset turns live without a run |

## 9. Where it runs

- **Controller** (API process, every replica): reads requests, plans runs.
  Holds no tenant state; claims rows with `SKIP LOCKED`.
- **Jobs**: scan runs of the built-in workflows, planned by the existing
  planner (capability → tool) and dispatched to the tenant's sensors or the
  platform scanning service by the usual routing (zones, `tenant_runner_only`,
  claim predicates). Passive lookups (`dnsx` through recursive resolvers,
  `rdap` and `asn` through the egress proxy) never contact a target host, so
  any eligible sensor may take them.
- **Platform-side collectors** that are not scans keep their own controllers
  (certificate transparency, EASM DNS-only checks); P1 lets a freshness
  request for a name move it to the front of their queues instead of adding
  a run.

## 10. Observability

- Metrics: `asset_enrichment_requests_total{reason}`,
  `asset_enrichment_dispatched_total{profile}`,
  `asset_enrichment_skipped_total{reason}` (disabled, budget, no_profile,
  cooldown), `asset_enrichment_runs_failed_total`,
  `asset_freshness_record_errors_total`, gauge
  `asset_enrichment_pending` per tick.
- Per asset: `GET /api/v1/assets/{id}/freshness` (`assets:read`, data scope
  of the asset) returns each class with `observed_at`, `source`, `ttl`,
  `state`, plus the request (`requested_at`, `dispatched_at`,
  `last_run_id`) and `next_due_at` (oldest live class + ttl).
- Runs are tagged `auto-enrichment` and visible in the runs list.
- Timeline: an enrichment that changes a value writes the RFC-069 change
  event through reconciliation; a re-sighting writes nothing.

## 11. UI

- **Asset detail → Freshness panel**: one row per class (state badge, last
  observed relative time, source tool, TTL), the request state ("queued",
  "enriched 5 min ago, run …"), and in P1 a "Refresh now" button.
- **Inventory filter** `Freshness: stale / never enriched`.
- **Attack surface → Monitoring card** (beside the certificate transparency
  and DNS-check switches): "Automatic enrichment" switch (passive, on by
  default) with an explanation; P1 adds the active opt-in with label picker.
- **Dashboard KPI** (P1): "Assets with stale data" with drill-down to the
  filtered inventory.
- All text through i18n (en, vi).

## 12. Threat model

| Threat | Control | Test |
|---|---|---|
| A tenant adds a third party's names (CSV, manual) to make the platform scan them automatically | Passive only by default and passive refuses names no scope entry covers; active needs opt-in, scope, governance and, on platform sensors, domain proof | `TestEnrichment_OutOfScopeNamesAreNotDispatched` |
| Cross-tenant leakage through requests, freshness rows or runs | Every query `WHERE tenant_id`; composite FKs to assets; runs created in the asset's tenant; freshness endpoint 404 for another tenant's asset | `TestFreshness_CrossTenantIsolation`, `TestAssetFreshnessHandler_OtherTenant404` |
| A member reads freshness of an asset outside their data scope | Endpoint uses the asset read path with data scope | handler test |
| Enrichment loop (DNS → address → network → …) or cost blow-up | Creation-only trigger, idempotent rows, cooldown, scope-bound chain, budget, per-run cap | `TestController_BudgetAndCooldown` |
| Flood of assets from a hostile sensor report fills the queue | One row per asset (bounded by the inventory), budget per day, per-run cap | `TestController_BudgetAndCooldown` |
| A program's rules bypassed by automatic runs | Rules applied at command delivery for every path | RFC-065 tests, unchanged |
| Privacy: registration data | `lookup.rdap` keeps no person names, e-mails, phones or addresses (unchanged); freshness rows hold only times and tool names | — |
| A disabled tenant still enriched | The switch is read at claim time; pending rows are drained without a run | `TestController_DisabledTenantDrains` |

## 13. Rollout

- Passive enrichment is on for every tenant on deploy. The first tick only
  sees assets created after the deploy; P1's staleness pass picks up the
  existing inventory within the budget, oldest and most important first.
- `ASSET_ENRICHMENT_ENABLED=false` turns the controller off for the platform.
- Freshness rows start empty; existing assets show `never` for passive
  classes until a report or enrichment observes them.

## 14. Phases

| Phase | Content | PRs |
|---|---|---|
| **P0** | Classes, `asset_attribute_freshness` recorded from every report; `asset_enrichment_requests` from every creation path; controller with budget and debounce; three passive profiles; EASM setting switch; freshness endpoint and stale filter; asset freshness panel, inventory filter, settings switch | migration + recorder + endpoint + filter; requests + controller + profiles + setting; web |
| **P1** | Staleness pass with priority and fair share; change-rate TTL factor; change chains (new address, DNS change, reappear, lifecycle verification, expiring registration); active opt-in by label with Probe web and Ports profiles; "Refresh now"; dashboard KPI | one PR each |
| **P2** | Endpoint discovery, code dependencies, screenshots; targeted checks after a new port; certificate re-probe; collectors' queues accept freshness requests | one PR each |

## 15. Open questions for the owner

1. Default daily budget: 2 000 assets per tenant per day for passive work,
   or a per-organization limit key (unlimited by default)?
2. Should the staleness pass (P1) refresh the existing inventory on deploy,
   or only assets created after it?
3. Active opt-in (P1): by asset label only, or also by asset group and by
   criticality?
4. Should a `needs_review` candidate be enriched passively automatically
   (proposed: yes, it helps the reviewer), or only after confirmation?
5. Do bug-bounty program targets ever get active enrichment automatically,
   or only through a person-started scan?
