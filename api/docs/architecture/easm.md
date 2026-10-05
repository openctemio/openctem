# External Attack Surface Management (EASM)

> **Status: design (RFC-036 Accepted 2026-10-02, owner decisions O1–O10 as
> recommended; implementation in progress in the monorepo, P0 first).**
> This document describes how EASM works in OpenCTEM today and the
> architecture RFC-036 builds towards. Each section marks what is **built**, what is **partial** and what is
> **planned**. The reasoning, the industry survey, the ranked gap list and the
> phased plan are in
> [RFC-036](../rfcs/RFC-036-easm.md). Update this page in the same PR whenever
> a phase ships.

EASM answers four questions about the internet-facing assets an organisation
owns or is responsible for:

1. **What do we have on the internet?** Discovery, starting from seeds.
2. **Is it really ours?** Attribution, with confidence and evidence.
3. **What is wrong with it?** Non-intrusive assessment.
4. **What changed?** Continuous monitoring.

The answers feed the existing CTEM registers (assets, exposures, findings) and
the P0–P3 priority engine. EASM adds no new score.

**Scope.** Only the customer's own attack surface, scanned under the customer's
authorization. Active scanning follows RFC-030 politeness and RFC-034 rules: the
scanner backs off when a target throttles or blocks it and never evades. A
third-party / vendor-risk mode is a separate owner decision (RFC-036 §7). If it
is ever built, it uses only passive public data.

## 1. Pipeline

```
 Scoping › Boundaries › Seeds                       (tenant-entered, verified where possible)
   │  org names, brands, root domains, ASNs, CIDRs, cloud accounts, GitHub orgs
   ▼
 ┌──────────────────────────── API side, passive: no packets to the target ─────────────┐
 │ Collectors (per tenant, scheduled controllers, SSRF-guarded, per-tenant keys)        │
 │   CT logs · passive DNS · RDAP · ASN/RIR · reverse DNS of owned ranges · cloud APIs  │
 │   · GitHub org · search engines of scan data (Censys/Shodan, tenant keys)            │
 │   · DNS-only checks (SPF/DMARC/MTA-STS, dangling CNAME, lookalike resolution)        │
 └──────────────────────────────────────┬───────────────────────────────────────────────┘
                                        ▼
                 Candidates + evidence ──► Attribution engine (rules, confidence 0–100)
                                        │      ≥ auto threshold, strong evidence → confirmed
                                        │      otherwise → review queue (confirm / reject /
                                        │      dependency / monitor only)
                                        ▼
                 Asset inventory (attribution_state, attribution_confidence, evidence)
                                        │
 ┌──────────────────────────── Sensor side, active: touches the target ─────────────────┐
 │ Discovery run per cadence tier, chained steps, RFC-030 chunks + politeness:          │
 │   resolve (wildcard-aware) → light ports → HTTP/TLS probe (+ certs, CDN, favicon,    │
 │   tech/CPE) → optional screenshot → nuclei, intrusiveness tier T1 by default         │
 │ Runs on a tenant sensor in the default (public) zone; optional shared platform       │
 │ sensors with published egress IPs (owner decision)                                   │
 └──────────────────────────────────────┬───────────────────────────────────────────────┘
                                        ▼
            CTIS ingest (RFC-026) → assets, relationships, findings, exposure events
                                        ▼
            Observations (facet hashes) → diffs → state history, exposure events,
            notifications, workflow triggers → P0–P3 priority → ticketing, validation
```

**Why the split.** Sending packets to a target belongs on a sensor: the sensor
sits in a scan zone, follows the RFC-030 politeness limits, and has the egress
that RFC-034 controls. The API sends no traffic to customer infrastructure. It
only calls third-party data sources and DNS resolvers. This keeps the control
plane's IP reputation out of scanning and reuses the SSRF-guarded client every
API connector already uses (`pkg/httpsec`).

## 2. What exists today (verified on `develop` 2026-10-02)

| Area | State | Where |
|---|---|---|
| Asset types `domain`, `subdomain`, `certificate`, `ip_address`, `service` (+ recon sub-types), `application`, cloud types | Built | `pkg/domain/asset/value_objects.go` |
| Discovery provenance on assets (`discovery_source`, `discovery_tool`, `discovered_at`, `first_seen`, `last_seen`) | Built | `pkg/domain/asset/entity.go` |
| Exposure fields (`exposure`, `is_internet_accessible`, exposure change timestamps) | Built | ingest `applyCTEMSignals`, `inferAssetExposure` |
| Relationships `contains` (root → subdomain), `resolves_to` (domain → IP); inferred `exposes`, `runs_on` | Built | `internal/app/ingest/processor_assets.go`, `internal/app/asset/relationship_inference.go` |
| Identity resolution (strong identifiers, 7-day IP window, conflicts to dedup review) | Built | RFC-001, RFC-028, [asset-identity-resolution.md](asset-identity-resolution.md) |
| CT monitoring: crt.sh, `subdomain_discovered` + `certificate_expiring` exposures | Built, with two limits (§6) | `internal/app/certmonitor`, [certificate-transparency-monitoring.md](certificate-transparency-monitoring.md) |
| Certificate assets → `certificate_expiring` / `certificate_expired` / `ssl_issue` exposures; service assets → `port_open` / `service_detected` | Built | `internal/app/exposurebridge/asset_bridge.go` |
| KEV + EPSS (global, daily), P0–P3 priority with internet-accessible and criticality | Built | `internal/app/threat`, `pkg/domain/vulnerability/priority.go` |
| Attack paths and exposure chains from public entry points | Built | `internal/app/attack/path_scoring.go`, `exposure_chains.go` |
| "What changed": state history, `asset_discovered` trigger, throttled new-internet-facing notification | Built | [change-detection.md](change-detection.md) |
| Scope targets and exclusions; exclusions fail closed on every scan | Built | `pkg/domain/scope`, `internal/app/scan/targets.go` |
| Scan zones, default zone for public targets | Built (RFC-023 P1) | [scan-zones.md](scan-zones.md) |
| Verified domains (DNS TXT, re-verified every 12 h) | Built, used only for SSO JIT | migration 000191 |
| Recon wrappers subfinder, dnsx, naabu, httpx, katana; nuclei takeover preset | Built in sdk-go, **not shipped** in any sensor image | sdk-go `pkg/scanners/recon`, sensor `internal/executor/recon.go` |
| Seeds / organisation model | **Missing** | — |
| Attribution confidence and evidence on assets | **Missing** (`asset_sources` has a confidence column but no writer) | migration 000014 |
| Passive sources other than crt.sh; cloud connectors | **Missing** (providers declared, no clients) | `pkg/domain/integration/entity.go` |
| Subdomain takeover (DNS part), email security (SPF/DMARC/MTA-STS/TLS-RPT) | **Built** (RFC-036 P1): daily DNS-only checks, [easm-dns-checks.md](easm-dns-checks.md) | `internal/app/easmdns` |
| Takeover confirmation on sensors, open buckets, lookalike domains | **Missing** | — |
| Chained discovery pipeline (step output → next step input) | **Missing** (steps share one context) | `internal/app/pipeline/run.go` |
| Change facets beyond appear/disappear/exposure (DNS, ports, certs) | **Missing**: `dns_change`, `port_closed`, `service_changed`, `subdomain_removed` have no producer | `pkg/domain/exposure/value_objects.go` |
| Hosted scanning from published IP ranges | **Missing**: `CanUsePlatformSensors` is false in OSS | `internal/app/adapters.go` |

### UI

| Page | State |
|---|---|
| `/attack-surface` | Real, over `GET /attack-surface/stats`; the trend fields are hard-coded 0 in the API |
| `/attack-surface/external` | Partial: client-side over the first 100 assets; the "Expiring certs" card is always 0 |
| `/assets/{domains,certificates,ip-addresses,websites,services}` | Real lists over `/assets?types=`; certificates without `not_after` show as valid; websites without a status show 200 |
| `/assets/changes` (What changed) | Real |
| `/attack-paths`, `/exposure-chains`, `/exposures` | Real |
| `/exposures/{vulnerabilities,secrets,code,misconfigurations}` | Partial: side cards show tenant-wide numbers |
| `/scope-config`, `/scoping` | Real |

No EASM page is a `useDashboardStats` scaffold. The planned pages (§7) must
each have their own endpoint. The UI CI test `sidebar-no-scaffolds` enforces
this for the sidebar.

## 3. Seeds and authorization (partly built)

A **seed** is a fact the tenant asserts about itself, and discovery starts from
it. Seed kinds: organisation name, brand, root domain, ASN, CIDR, cloud
account, GitHub organisation, mobile publisher, analytics or tag ID, favicon
hash. Seeds sit in Scoping › Boundaries next to targets and exclusions.

| Ownership proof | What it allows |
|---|---|
| None (asserted) | Passive collection; T1 active assessment of confirmed assets |
| DNS TXT (`verified_domains`, reused from SSO) or cloud connector | Auto-confirmation of names under the domain; eligible for T2 intrusive checks on opt-in |

Exclusions always win, as today. An asset is actively scanned only when it is
attributed `confirmed` and either inside a scope target or derived from a seed.
Candidates and dependencies get passive (T0) checks only.

**Built (P2 slice 1, migration 000700).** `easm_seeds` holds one row per
(tenant, kind, value) with a label, `discovery_enabled`, and who attested the
organisation's authority over it and when. The schema lists every RFC kind;
the API accepts only kinds something consumes, today **`root_domain`**: the
Certificate Transparency monitor watches it (origin `easm_seed`, asserted:
names under it get `fqdn_under_asserted_root` and wait for review unless a
verified domain covers them). CIDR, ASN and organisation seeds arrive with
their collectors, so no seed sits unused.

| Route | Permission | |
|---|---|---|
| `GET /api/v1/easm/seeds` | `attack_surface:scope:read` | with `verification` (`dns_txt` while the tenant has a verified DNS TXT record for the domain or a parent; computed on read, never taken from the client) |
| `POST /api/v1/easm/seeds` `{kind, value, label?, discovery_enabled?, attested: true}` | `attack_surface:scope:write` | refuses public suffixes, providers' shared domains (private PSL suffixes) and names without an ICANN suffix; at most 500 per tenant; audited `easm_seed.created` (high) |
| `PATCH /api/v1/easm/seeds/{id}` `{label?, discovery_enabled?}` | `attack_surface:scope:write` | audited `easm_seed.updated` |
| `DELETE /api/v1/easm/seeds/{id}` | `attack_surface:scope:delete` | assets found from it stay; audited `easm_seed.deleted` |

All behind the `attack_surface` module. Two tenants may seed the same domain:
nothing about another tenant's seed or verification is ever shown. Code:
`pkg/domain/easmseed`, `internal/app/easm/seeds.go`,
`internal/infra/postgres/easm_seed_repository.go`.

**Web.** Scoping › Boundaries (`/scope-config?tab=seeds`) has a **Seeds** tab
when the `attack_surface` module is on: the list with ownership (verified by a
DNS TXT record, or asserted), a discovery switch, and Add seed, which stays
disabled until the attestation box is ticked. Code:
`web/src/features/attack-surface/components/easm-seeds.tsx`.

## 4. Attribution

**Built (P0, migration 000324).** `asset_attributions` holds per asset a
state, a confidence 0–100 and the strongest rule; `easm_evidence` holds one row
per (asset, rule, source) with the technique, the source and the observed
datum. It is a side table, not columns on `assets`: the asset write paths each
list their columns, and a column one of them forgets is silently dropped. An
asset without a row is a legacy asset and counts as confirmed, so nothing in
the inventory changed meaning.

| Piece | Where |
|---|---|
| Rules, noisy-OR, O4 decision, `Merge` (automation only raises; a human decision stands) | `pkg/domain/attribution` |
| Storage, tenant-scoped writes (a foreign asset id writes nothing) | `internal/infra/postgres/attribution_repository.go` |
| First producer: CT promotion (`fqdn_under_verified_root` 0.99 → confirmed; `fqdn_under_asserted_root` 0.85 → needs_review) | `internal/app/certmonitor/promote.go` |
| Second producer: sensor reports (owner decision O8 as narrowed by research/22 E7). A report bound to a command the tenant's own sensor ran: an asset that **is** one of the command's targets (same host or repository path, or an address inside a listed range) gets `tenant_scanned` (0.95, strong) with sensor, command, step run, pipeline run, scan, tool, report id and time; an automatic record is re-evaluated unless it is `needs_review` or `rejected` (a scan never takes a name past review). A name the scan **found** under a target (subfinder child, resolved address, auto-created root domain) gets `tenant_scan_discovered` (0.60, medium, never confirms alone); a new internet-facing one gets a `needs_review` record, or `confirmed` with `fqdn_under_verified_root` evidence when it is at/under a verified domain. An unsolicited sensor report gives a new internet-facing asset a `candidate` record and no evidence. A person's decision is never touched; an existing asset without a record keeps none. Server-side ingests (CT promotion, uploads) never come here. `root_domain` in a report must be a registrable strict parent of the reported name (`publicsuffix`), otherwise no domain is created | `internal/app/ingest/scan_attribution.go`, `internal/app/easm/scanned.go`, `internal/infra/postgres/easm_scan_evidence_repository.go` |
| CT roots from domain assets: only approved ones (not `needs_review`, `candidate` or `rejected`), so a sensor-created domain cannot widen the CT watch list | `internal/app/certmonitor/service.go` (`gatherRoots`) |
| Active-scan ownership gate on every active-scan path (typed targets and group members alike): refused when the asset's record is not `confirmed`, when the name or a parent of it was rejected (record or live tombstone), and when an internet-facing asset has **no record** and is neither inside an active scope target nor at/under a root-domain seed or verified domain (`unattributed`). Create, clone, import, quick scan and `POST /commands` refuse the request; a run skips the target with a warning; the dispatch gate refuses it. Generic reason to the caller, specific state in the log. Details: [active-probe-gate.md](active-probe-gate.md) | `internal/app/easm/active_gate.go`, `internal/app/scan/ownership.go` |
| `GET /api/v1/assets/{id}/attribution` (assets:read) and `PUT` (assets:write, audited `asset.attribution_decided`) | `internal/infra/http/handler/asset_attribution_handler.go` |

**Rejection tombstones (P2, migration 000775).** When a person marks a
domain or subdomain as not the tenant's (asset page or review queue), the
lowercased name and the rules that supported it are kept in
`easm_tombstones`, in the same transaction as the decision. CT promotion does
not propose that name again, even after the asset is deleted, unless it is now
supported by a rule that was not there at rejection (for example the domain
was verified since). Reversing the rejection removes the tombstone; tombstones
expire after 12 months (O7) and each CT sweep purges the tenant's expired
rows. A failed tombstone lookup promotes nothing. All statements are
tenant-scoped (`internal/infra/postgres/easm_tombstone_repository.go`).

**Asset merges** (dedup review, RFC-028) keep attribution: the kept asset
takes the most recent human decision of any merged asset (older decisions stay
in the audit log); without one it keeps its own record, and merged assets'
automatic records are dropped, never demoting a legacy asset. Evidence moves to
the kept asset, one row per (rule, source) with the earliest first sighting
(`mergeAttribution` in `internal/infra/postgres/asset_merge_plan.go`).

Deviation from the plan below, on the owner's instruction for P0 (feed CT
names into the asset pipeline, marked unconfirmed): names found under a domain
the tenant did not verify enter the inventory as `needs_review` assets rather
than as candidates outside it. The scan gate keeps them passive. P2's
`easm_candidates` is still where weak (< 50) names will live.

**Planned (P2).** Each candidate carries **evidence** rows (kind, source, observed value, weight,
time). Confidence is the noisy-OR of the evidence weights,
`1 − Π(1 − wᵢ)`, shown as 0–100. Weights start from a rule table (for example:
name under a verified root ≈ 0.99, IP in a seeded CIDR/ASN ≈ 0.9, resource
returned by the tenant's cloud connector = 1.0, TLS SAN shared with a confirmed
name ≈ 0.5, favicon hash match ≈ 0.4). Shared-hosting or CDN evidence counts
against the candidate and points to the `dependency` state.

States: `candidate` → `confirmed` | `rejected` | `dependency` (ours by name,
infrastructure is a provider's) | `monitor_only`. Only strong evidence classes
auto-confirm; everything else goes to the review queue. A rejection is kept as
a tombstone, so the same candidate is not proposed again unless a new kind of
evidence appears. Each rule's precision is learned per tenant from
confirm/reject decisions (a Beta prior per rule), and that adjusts its weight.

Candidates live outside the asset table. A confirmed candidate becomes an asset
through the normal ingest path, so there is still one asset-creation path (the
concern RFC-019 §6 raised). Assets created by tenant-triggered scans keep the
current behaviour and get evidence stamped on them.

## 4a. Overview API (built, P1)

`GET /api/v1/easm/summary` (assets:read, `attack_surface` module, data scope)
answers the overview in one call: surface assets by type (`domain`,
`subdomain`, `ip_address`, `certificate`) and internet-facing services;
attribution counts (legacy assets without a record count as confirmed and are
also reported separately) with the age of the oldest review item; assets first
seen in the last 7 and 30 days and since the latest CTEM cycle was activated
(absent when there is no cycle, never a misleading 0); open external exposures
by severity and type; the ten most severe open external exposures; and CT
monitoring freshness (`ct_monitor_state`). Code: `internal/app/easm`,
`internal/infra/postgres/easm_summary_repository.go`.

## 4b. Review queue and inventory filter (built, P1)

Until P2 adds `easm_candidates`, the review queue is the set of inventory
assets whose attribution is `needs_review` or `candidate`.

| Route | Permission | Behaviour |
|---|---|---|
| `GET /api/v1/easm/candidates?states=&types=&min_confidence=&search=` | `assets:read` | Most confident first, each row with its evidence. Default states `needs_review,candidate`; `states=rejected` lists rejections for undo |
| `POST /api/v1/easm/candidates/decisions` `{asset_ids ≤ 200, state, note?}` | `assets:write` | One statement upserts a human decision for each asset that is the tenant's and not deleted; automation never changes it afterwards. One `asset.attribution_decided` audit event per asset (from, to, `via=review_queue`, the note) |
| `GET /api/v1/assets?attribution=` | `assets:read` | `confirmed` (includes assets with no record), `needs_review`, `candidate`, `dependency`, `monitor_only`, `rejected`, `unknown` (no record), `unconfirmed` (= needs_review + candidate), `approved` (= confirmed + unknown + dependency + monitor_only) |

Both EASM routes sit behind the `attack_surface` module. **Isolation:** every
query pins `tenant_id`; the caller's data scope narrows the queue
(`user_accessible_assets`, as for the asset list) and filters the decision's
asset ids first (`datascope.Enforcer.FilterForCaller`). An asset outside the
scope, of another tenant or deleted is returned in `not_found`; the three cases
look the same. A data-scope lookup error fails the request. Code:
`internal/app/easm/review.go`, `internal/infra/postgres/easm_review_repository.go`.

**Web.** `/attack-surface/review` (assets:read, `attack_surface` module) lists
the queue with each row's evidence in words, with tabs for "Awaiting review"
and "Not ours" and bulk Confirm / Not ours / Dependency / Monitor only for
assets:write; the Overview's "Needs review" row links to it. The asset
inventory (`/assets`) shows only the organisation's assets by default
(`attribution=approved`): names awaiting review and rejected names are hidden
behind a "Show all" link, and the filter panel has an Attribution facet.
Code: `web/src/features/attack-surface/components/easm-review-queue.tsx`,
`web/src/features/assets/lib/inventory-url.ts` (`attributionQuery`).

## 4c. Alerts (built, P0-7)

EASM exposures reach the notification outbox (research/22 P0-7, owner
decision E4). The CT monitor, the DNS checks and takeover confirmation write
exposures through `postgres.EASMExposureWriter`; the DNS checks' reopen goes
through `EASMDNSRepository.ReopenAuto`. Both enqueue in **the same
transaction** as the exposure write, and only for rows that were **inserted**
(`xmax = 0` on the upsert) or **reopened** by the check. A re-sighting
announces nothing; a rollback leaves neither row.

| Exposure | Alert |
|---|---|
| Asset rejected ("Not ours") or deleted | never |
| Medium or higher on an approved asset (confirmed, dependency, or no record) | `new_exposure` now, one per exposure (`aggregate_type` `exposure`, URL `/exposures/{id}`) |
| Low or info; asset `needs_review`/`candidate` (labeled `unverified`) or `monitor_only`; exposure linked to no asset (`unlinked`) | the tenant's daily digest |
| Immediate alerts past 30 per tenant per rolling hour | the digest, counted as `throttled` |

The **digest** is one `notification_outbox` row per tenant and day
(`aggregate_type` `easm_digest`, due at 08:00 UTC, unique while pending:
`uq_notification_outbox_easm_digest`, migration `000980`). Each digest-class
exposure updates it: exact count, counts by severity and by attribution
label, up to 25 named items, the highest severity. It goes out as
`new_exposure` like the immediate alerts, so integrations that receive
`new_exposure` (a default-enabled type) get EASM alerts with no setup, and
their severity filter applies.

Payload metadata: `channel` `easm`, `exposure_id`, `event_type`, `severity`,
`source` (`cert_transparency`, `easm_dns`), `attribution` (state or label),
`reason` (`new`/`reopened`), `asset_id`/`asset_name`, `fingerprint`.

**Tenant isolation.** The alerter loads exposures with the tenant id in the
query, so ids of another tenant announce nothing; the throttle counter
(`easm_alert_throttle`) and the digest are per tenant. The throttle row is
locked for the transaction, which serializes one tenant's alert writes.
Policy: `pkg/domain/easmalert`; tests: `internal/infra/postgres/easm_alert_db_test.go`.

## 5. Data model (planned)

- **Graph.** Reuse `assets` + `asset_relationships`. Add asset types `asn` and
  `netblock`, and relationship types `announced_by` (IP/netblock → ASN),
  `serves_certificate` (service → certificate), `hosted_by` (asset →
  provider/CDN) and `cname_of` (emitted by DNS resolution). OWASP Amass' Open
  Asset Model is the reference vocabulary.
- **Observations.** Append-only per (asset, facet), where the facets are DNS
  record set, open ports, TLS certificate, HTTP fingerprint, technology set and
  WHOIS/RDAP. Each observation stores a canonical hash. A change of hash is a
  diff, and the diff writes state history and the matching exposure event.
- **Evidence.** `easm_evidence` keyed by tenant and subject (candidate or asset).
- **Time.** `first_seen`/`last_seen` per asset and per observation; the CT
  `not_before` and the passive-DNS first-seen give the earliest external
  evidence, which is what MTTD is measured against.

## 6. Known limits of what is built

- ~~The CT monitor queries only the first 50 domain assets per tenant.~~
  Fixed in RFC-036 P0: it watches domain assets, verified domains and domain
  scope targets, rotates through all of them (`ct_monitor_state`), retries
  crt.sh and falls back to Cert Spotter. See
  [certificate-transparency-monitoring.md](certificate-transparency-monitoring.md).
- ~~CT discoveries stay exposure events.~~ Fixed in RFC-036 P0: CT names
  become `subdomain` assets with attribution (§4).
- Sensor images ship no recon binaries. The recon executor is off by default
  but advertises recon capabilities when it is turned on. Pipeline steps do not
  feed one step's output into the next.
- httpx's favicon, JARM, ASN and certificate fields are parsed and dropped
  (`core.LiveHost` has no fields for them). No certificate asset comes from a
  live TLS handshake.
- Nothing sets asset scope `external` or `shadow` automatically, so the
  "Shadow IT" change view is empty.

## 7. UI (planned)

Discovery › Attack Surface becomes the EASM workspace. Tabs:

| Tab | Backed by |
|---|---|
| Overview | `GET /easm/summary`: attributed assets, review queue size, new in 7 days, exposures by severity, freshness, coverage |
| Inventory | `/assets` filtered to external, attribution columns |
| Review | `GET /easm/candidates` + evidence; confirm / reject / dependency / monitor only; bulk |
| Graph | `GET /easm/graph?root=` (seed → domain → subdomain → IP → service → certificate) |
| Changes | `/state-history/*` + facet diffs |
| Exposures | `/exposures?source=easm` and EASM findings |

Seeds are edited in Scoping › Boundaries.

## 8. Related

- [RFC-036](../rfcs/RFC-036-easm.md): the design, survey, gap list, phases and decisions.
- [RFC-019](../rfcs/RFC-019-certificate-transparency-discovery.md) / [certificate-transparency-monitoring.md](certificate-transparency-monitoring.md)
- [change-detection.md](change-detection.md), [scan-zones.md](scan-zones.md), [asset-identity-resolution.md](asset-identity-resolution.md)
- [RFC-030](../rfcs/RFC-030-scan-work-distribution.md) (politeness), [RFC-034](../rfcs/RFC-034-sensor-network-egress.md) (egress, no evasion)
- ADR-004 [finding provenance](decisions/004-finding-provenance.md): EASM is a technique (`findings.source = easm`), not a channel.
