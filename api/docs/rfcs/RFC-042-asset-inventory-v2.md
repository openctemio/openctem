# RFC-042 — Asset Inventory v2: services as rows, observations over time, one query language, labels, dynamic groups, policies and screenshots

> Status: **Accepted** (2026-10-03; owner decisions D1–D21 approved as
> recommended, §12). Implementation starts with the P0 slices in §9.1.
> **Amended 2026-10-03 by §6.3.8 (type model hardening)**: aliases are
> input-only, sub-types are closed lists, owner decisions O1–O6 and the
> ordered plan T0–T8.
> Scope: api (data model, query compiler, facets, groups, policy engine,
> target gate, screenshots store, rollups) + web (inventory pages; the UI
> design is in a companion document) + sensor (screenshot capture, HTTP/TLS
> fields kept) + sdk-go/ctis (wire fields).
> Builds on [RFC-028](RFC-028-asset-identity-model.md) (identity and merge),
> [RFC-030](RFC-030-scan-work-distribution.md) (claim-time chunks),
> [RFC-031](RFC-031-managed-sensor-updates.md) (content versions),
> [RFC-033](RFC-033-sensor-manifest.md) (manifest),
> [RFC-034](RFC-034-sensor-network-egress.md) (egress profiles),
> [RFC-036](RFC-036-easm.md) (EASM: seeds, attribution, observations, tiers)
> and [RFC-041](RFC-041-api-path-design.md) (API path conventions,
> [api-conventions.md](../architecture/api-conventions.md)). Working reference:
> [architecture/asset-inventory-v2.md](../architecture/asset-inventory-v2.md).
> UI companion: `web/docs/ui/inventory-integrations-2026-10.md`
> (service cards, facet menu, group-by chips, integrations catalog), written
> in parallel; this RFC owns the data model, the engines and the APIs.
>
> Owner's request (2026-10-03): redesign how assets are discovered,
> modelled, labelled, grouped, excluded, governed by policies and presented.
> Keep OpenCTEM's deeper CTEM model. Owner rule for every number on screen:
> **honest**.
> A metric whose inputs are empty says "insufficient data"; it never shows a
> default.

## 1. Answer in short

**Describe every asset type once, in a registry the API serves; keep one
unified core across all types; make the service (`host:port`) a
first-class, typed row for the external surface; record what was
seen over time as change-only observations; put one query language under
search, facets, saved filters, dynamic groups, policies, exports and the
API; and route every scan target, from any source, through one gate that
applies ownership, exclusions, lifecycle and budgets at dispatch time.**

0. **Many types, one registry, several lenses.** OpenCTEM has 37 asset
   types; repositories, hosts and networks are as common as web services.
   - A fixed **class** sits above each type (16 classes, an abstract kind
     above the concrete type). The classes are grouped into 8 **lenses**:
     external surface, applications, cloud & infra, containers & K8s,
     code, identities, data, network.
   - One **type registry** (YAML + codegen, served by the API) declares
     each type's class, attribute schema, facets, renderers, detail
     sections, relationships and identity keys.
   - Every type shares a **unified core**: owner, effective criticality,
     attribution, exposure, labels, first and last seen, sources and
     findings.
   - The service card is **one lens** (External surface), next
     to Code, Cloud, Identities and the others.
   - A typed relationship graph walks from a domain to the repository
     whose code runs behind it (§6.3).
1. **Three layers.** *Assets* keep identity (RFC-028), ownership,
   criticality and attribution. *Services* are the rows of the
   External-surface lens: one per host and port, with typed HTTP, TLS and
   network columns. The
   existing `asset_services` table is evolved for this; today nothing in
   ingest writes it. *Observations* record what was seen and when; a row
   is written only when the value changes. This is RFC-036's
   `easm_observations` with the subject widened from assets to services.
2. **One query language (OQL).** A small, typed grammar
   (`tech:jquery tech.version<3.5 port:443 -label:staging ip:10.0.0.0/8`).
   It compiles through a field registry into parameterised SQL. Search,
   facets, saved filters, dynamic groups, policies, exports, "scan this
   selection" and the public API all use the same compiler.
3. **Facets and group-by on the server**, with value counts that respect
   the caller's data scope. Narrow typed columns and tenant-leading indexes
   do the work. Unfiltered counts come from a per-tenant materialised table
   that states its `as_of`. When a count would be slow, the response says it
   is a lower bound ("10,000+"); it never invents a number.
4. **Labels with provenance.** *System labels* come from a versioned rule
   set (fingerprints plus OQL conditions); each assignment records the rule
   version, the evidence and a confidence. *Custom labels* are today's
   tags. A bulk label from a filter is one server call, not one PUT per
   asset.
5. **Groups: static and dynamic, both scannable.** A dynamic group is a
   saved OQL query, resolved **at dispatch**. Every resolved target then
   passes the ownership gate (RFC-036), exclusions and the lifecycle check.
   Sharing uses RBAC and data scope,
   never public links.
6. **One exclusion model, three enforcement points:** discovery (nothing
   new is created or pivoted from), dispatch (nothing is probed), and the
   discovery graph (excluding a node cuts what was reachable only through
   it). Already-inventoried matches are **archived with a reason**, never
   deleted, and come back if the exclusion is removed.
7. **A policy engine** with AND/OR conditions in OQL. Actions: label,
   notify, archive, mark out of scope, set criticality or owner, trigger a
   scan. Triggers: on discovery, on change, on a schedule. Scope: future
   only, or existing plus future. A **dry-run preview is required before
   enabling**. Every action is audited, and caps, a depth limit and a
   circuit breaker stop runaway policies.
8. **Screenshots captured on the sensor** in a sandboxed headless browser
   pinned to the scanned address. They are re-encoded on the API (WebP
   only, never SVG, size-capped) and served from an authorised path with a
   locked-down CSP. Perceptual-hash clusters build the "similar pages"
   gallery. Retention is 30 days (RFC-036 O7).
9. **Change detection** turns observation diffs into typed changes: new
   asset, new or closed port, certificate expiring or changed, technology
   added, removed or upgraded, title or status changed. These feed alerts,
   policies and daily rollups for the trend charts.
10. **Source records, correlation and the canonical row stay separate**,
    following the practice in §4.1:
    - per-source records live in new tenant-scoped `asset_source_records`
      and `service_sources` tables (the old, never-written `asset_sources`
      was dropped by the `drop_asset_sources` migration);
    - a single-flight correlation job per tenant and zone joins them,
      with deterministic, time-windowed keys and the zone as a hard
      boundary for private addresses;
    - it then recomputes the preferred fields of the canonical row.
    Manual merge and split are both audited.

| | Today (verified 2026-10-03, `develop` d547a60) | With this RFC |
|---|---|---|
| A web service | an asset of type `service`/sub-type `http` named after a URL, plus loose keys in `assets.properties` | a `services` row: host, port, transport, HTTP/TLS/network columns, labels, technologies, screenshot |
| What changed | `asset_state_history` (appeared, disappeared, exposure); title, tech, certificate or port changes are merged in silently | change-only observations per facet, typed diffs, alerts |
| Filtering | fixed query parameters; `search` is `ILIKE` | OQL everywhere, with the same semantics in the UI, API, policies and groups |
| Facet counts | none in the UI; `/assets/facets` expands every JSONB key of every asset per request and ignores data scope | server facets on typed columns, data-scope aware, with `as_of` and lower-bound flags |
| Groups | static only (`group_type` dropped in 000205) | static + dynamic, both scannable through the gate |
| Exclusions | enforced only at scan trigger; ingest, CT discovery, pipeline runs and the coverage dispatcher bypass them | discovery + dispatch + graph cut; archive matches |
| Automation on assets | workflows can only act on findings; nothing labels or archives assets | asset policies with preview, audit and caps |
| Screenshots | none (the gowitness preset step was removed in 000270) | sandboxed capture, safe storage, clusters |

## 2. Scope

In scope:

- the inventory data model;
- the query language and its compiler;
- facets, group-by, saved filters, labels, groups, exclusions, policies,
  screenshots, change detection and rollups;
- the APIs for all of the above;
- the sensor's screenshot capture and the HTTP/TLS fields it must keep.

### 2.1 Non-goals

- **Attribution, seeds and the candidate review queue.** RFC-036 owns
  them. This RFC defines how associated-domain *evidence* is shown and how
  candidates surface in the inventory, and it widens RFC-036's lineage to
  inventoried assets (§6.9). It adds no second queue.
- **Pixel-level UI.** The companion UI document owns it.
- **Cloud connectors.** RFC-036 P5 owns them. They are an input here.
- **A general-purpose rule engine.** Policies are a bounded, declarative
  set of actions over inventory rows. Workflows (`internal/app/workflow`)
  stay the imperative tool for findings.
- **Hard delete from automation.** No policy, exclusion or lifecycle path
  deletes an asset. Deletion stays a human action under `assets:delete`,
  and since owner decision O3 (2026-10) a human delete never destroys
  findings: an asset with findings is refused (archive it), one without is
  soft-deleted and purged after 30 days (`architecture/asset-deletion.md`).

## 3. Current state (verified 2026-10-03: `develop` d547a60; ctis `main` 272ae51; sensor `main` ca3d576)

Paths are relative to the repository root unless another repository is
named.

### 3.1 Data model

- **F1. The services table exists but no ingest path writes it.**
  `asset_services` (`api/migrations/000009_asset_extensions.up.sql:82-132`)
  has port, protocol, product, version, banner, CPE, TLS, `last_seen_at`,
  state and `technologies TEXT[]` with a GIN index (`000070:5-8`).
  `AssetServiceRepository.UpsertBatch`
  (`api/internal/infra/postgres/asset_service_repository.go:366`) has no
  callers. Only the manual CRUD routes write it
  (`api/internal/infra/http/routes/assets.go:397-414`).
- **F2. Ingest models a web service as an asset.**
  - Ports go into `properties.ports` (`api/internal/app/ingest/mappers.go:394`).
  - httpx results become assets of type `service` with sub-type `http`,
    `open_port` or `discovered_url`
    (`api/pkg/domain/asset/value_objects.go:109-111`).
  - HTTP fields (status, title, web server, content length, technologies,
    CDN, IP) are loose keys in `assets.properties`
    (ctis `recon_converter.go:540-600`;
    `api/internal/app/ingest/processor_assets.go:1890-1962`).
- **F3. Technologies are copied into user tags.**
  ctis `recon_converter.go:585` appends every detected technology to
  `asset.Tags`. Fingerprints and human labels share one namespace, so a
  "jQuery" tag cannot be told apart from a label someone chose.
- **F4. Fields are dropped on the way in.**
  - The sdk-go httpx parser drops favicon hash, ASN and TLS certificate
    data, because `core.LiveHost` has no fields for them (sdk-go `main`
    1053850, `pkg/scanners/recon/httpx/scanner.go:481-588`,
    `pkg/core/interfaces.go:885`).
  - CTIS has no HTTP block and no CDN or favicon field. TLS appears only
    as three strings on `ServiceTechnical` (ctis `types.go:488-513`).
- **F5. No property-level history.** `asset_state_history`
  (`000009:141-176`, change types widened at `000243:48-54`) records
  appearance, disappearance and exposure changes only. A changed title,
  technology, certificate or port set is merged into `properties` with no
  record (`processor_assets.go:1852-1855`).
- **F6. Findings do not know their port.** CTIS carries `Finding.Network`
  (host, port, protocol, service; ctis `types.go:1004`, `:1429-1445`), but
  ingest uses the port only inside the VA dedup fingerprint
  (`api/internal/app/ingest/processor_findings.go:797-798`). No findings
  column holds it, so "issues found on this service" cannot be answered.
- **F7. Name is unique per tenant regardless of type**
  (`000008_assets.up.sql:136`). RFC-028 lists this as a known limit
  (`RFC-028-asset-identity-model.md:148-150`).
- **F8. The merge plan is guarded.** `mergeAssetReferences`
  (`api/internal/infra/postgres/asset_merge_plan.go:45-116`) moves 12
  tables as they are, 11 with unique-key handling (including
  `asset_services` and `asset_group_members`), plus edges and special
  cases. `api/tests/integration/asset_merge_coverage_test.go` fails when a
  new FK to `assets` is not in the plan. Every table this RFC adds that
  references assets must join the plan.

### 3.2 Query, facets and bulk actions

- **F9. Search is substring matching.** `search` is `ILIKE` on name and
  description plus an exact alias match
  (`api/internal/infra/postgres/asset_repository.go:1103-1109`).
  `pg_trgm` is installed (`000001:8`) but no index on `assets` uses it.
- **F10. Facets do not scale and ignore data scope.**
  - `GET /assets/facets` → `GetPropertyFacets`
    (`asset_repository.go:2177-2230`) expands every JSONB key and every
    array element of every asset in the tenant on each request.
  - `GET /assets/stats` → `GetAggregateStats` (`:1951-2143`) filters only
    by type, tag and sub-type.
  - Both pass only the tenant id (`api/internal/app/asset/service.go:1396-1414`),
    while the list applies the user's data scope (`service.go:1374-1381`;
    SQL at `asset_repository.go:1315-1334`). A scoped user can therefore
    read counts of assets they cannot list.
- **F11. The UI shows no facet counts on purpose.** "the stats counts
  ignore the other active filters, so they would disagree with the list"
  (`web/src/features/assets/components/inventory/inventory-facet-panel.tsx:15-17`).
  Saved views are "intentionally deferred to v2"
  (`web/src/features/assets/components/inventory/all-assets-inventory.tsx:12`).
- **F12. Bulk tagging is N requests.** The only bulk asset routes are
  `/bulk/sync` and `/bulk/status` (`routes/assets.go:37-38`). The bulk bar
  sends a full PUT per asset in client-side batches
  (`web/src/features/assets/components/inventory/inventory-bulk-bar.tsx:86-107`).
- **F13. Pagination is offset-only and capped at 100**
  (`api/internal/infra/http/handler/common.go:185`). The list's finding
  count is a LATERAL subquery per row (`asset_repository.go:453-473`).

### 3.3 Groups, scope and exclusions

- **F14. Groups are static only.** `asset_group_members` is the only
  membership (`000024:44-49`). `group_type` and `properties` were dropped
  because "the 'dynamic' rule-based value it was meant to enable was never
  implemented" (`000205_drop_dead_asset_taxonomy_columns.up.sql:10-13`). The asset-group repository never
  applies data scope.
- **F15. Group scans resolve at trigger, by name, with no lifecycle
  filter.**
  - `resolveScanTargets` (`api/internal/app/scan/targets.go:63-145`) pages
    group members (`trigger.go:1107-1135`), subtracts approved exclusions
    (fail-closed) and caps at 10,000 (`targets.go:18`).
  - Members are matched by `name` only. A hostname whose address falls in
    an excluded CIDR is not excluded.
  - Stale and archived members are scanned.
- **F16. Exclusions are bypassed on four paths.**
  - Ingest has no scope or exclusion check, so excluded hosts that are
    already in the inventory stay there unflagged.
  - CT discovery reads scope targets but not exclusions
    (`api/internal/app/certmonitor/service.go:443-452`).
  - `POST /pipelines/runs` passes user targets straight into step payloads
    (`api/internal/app/pipeline/run.go:1100-1101`).
  - The Tenable coverage dispatcher bypasses it
    (`api/internal/app/scancoverage/scheduler.go:242-249`).
  - Nothing re-checks at claim time: RFC-030's `scan_run_targets` is
    written once at trigger.
- **F17. Wildcard semantics are surprising.** `*.x` also matches the bare
  `x`, and `**.x` behaves exactly like `*.x`
  (`api/pkg/domain/scope/value_objects.go:358-380`). The exclusion types
  `finding_type` and `scanner` are matched against target strings like
  host patterns.
- **F18. The approval workflow works.** Migration 267 adds `pending` and
  `rejected` and the permission `attack_surface:scope:exclusions:approve`
  (`000267_scope_exclusion_approval.up.sql:20-46`). A requester cannot
  approve their own exclusion (`api/internal/app/scope/service.go:462-465`).
  This RFC keeps the workflow unchanged.
- **F19. Attribution gate in flight.** PR #835 adds `asset_attributions`
  and `easm_evidence` (migration 000324) and a gate inside
  `resolveScanTargets` that skips unconfirmed group members. Direct
  targets stay ungated (RFC-036 O8). Validation re-checks and pipeline
  hops are not covered yet.

### 3.4 Automation, notifications, storage

- **F20. Nothing acts on assets automatically.**
  - The lifecycle worker (`api/internal/app/asset/lifecycle_worker.go:136`)
    moves active to stale but never archives.
  - Workflow tag actions act on findings only
    (`api/internal/app/workflow/action_handlers.go:60-75`).
  - Workflows have per-tenant run caps (`service.go:19-23`) but no loop
    protection: an action can re-fire its own trigger.
- **F21. Change events are defined but never produced.** The notification
  types `asset_changed` and `asset_deleted` exist
  (`api/pkg/domain/integration/notification_extension.go:95-163`), but
  nothing emits them. `new_asset` is emitted with an in-memory 15-minute
  throttle per API replica (`api/internal/app/assetdiscovery/notifier.go:46`,
  `:315`).
- **F22. A storage abstraction exists.**
  - `FileStorage` with local, S3 and MinIO backends
    (`api/pkg/domain/attachment/storage.go:19-42`; `api/internal/infra/storage/`).
  - Uploads have a 10 MB cap and a type allowlist without SVG
    (`storage.go:116-142`).
  - Images download inline with `nosniff` (`attachment_handler.go:218-262`).
  - The global CSP is `default-src 'none'; frame-ancestors 'none'`
    (`api/internal/infra/http/middleware/security.go:46`).
- **F23. No screenshots and no recon binaries.**
  - The sensor image installs semgrep, betterleaks, trivy and nuclei only
    (sensor `main` `Dockerfile`; `tool_detect.go:19`).
  - Migration 000270 claims otherwise and removes the gowitness preset
    step (`000270_recon_tools_shipped_presets.up.sql:4-12`).
  - RFC-036 P0 (E2) is the fix. Screenshots here depend on it.

### 3.4a Types and taxonomy

- **F24. Four taxonomies disagree, and type pages are hand-coded.**
  - Go `category.go` defines 9 derived categories.
  - The DB `asset_type_categories` table has 8 different codes, with no
    `external_surface` and no `network`.
  - The web `category-templates.tsx` has 7 groups that place database,
    service and Kubernetes differently.
  - `relationship-types.yaml` constrains on virtual types the backend
    cannot enforce.
  - The 25 typed pages each hand-code columns and sections in their own
    `config.tsx`.

  Details and file:line are in §6.3.1.

### 3.5 Facts the design depends on

- **Effective criticality** is computed at read time as the MAX of asset,
  BU, business service and served control-plane criticality
  (`api/pkg/domain/asset/business_criticality.go:53-71`). Policies that
  "set criticality" set the asset's own value; the effective value
  follows.
- **Scope and assignment rules key on `assets.tags`**
  (`000074` `group_asset_scope_rules`; `000044:108` `assignment_rules`).
  Custom labels must stay in `assets.tags`, or both engines break.
- **Open PRs reserve migrations 000273–000327.** This RFC uses names, not
  numbers; numbers are assigned when each phase is implemented.

## 4. Requirements and design practices

The inventory loop is **filter → bulk act (label, status) → save as a
dynamic group → policy**. Labels and screenshots are asynchronous, driven by
the change worker (§6.15.4) and a pipeline step (§6.14). Each area has a
requirement this RFC meets:

| Area | Requirement |
|---|---|
| Model | Services (`host:port`) are the browsing unit with a rich HTTP/TLS card, tied to assets that carry ownership, criticality, attribution and findings (P0–P3) |
| Associated domains | Evidence-backed candidates with noisy-OR confidence, accept / reject / dependency, tombstones, no artificial cap (RFC-036 P2, §6.10) |
| Screenshots | Sandbox spec, safe storage, perceptual clusters, 30-day retention, all documented (§6.14) |
| Auto labels | Versioned rule set, rule version + evidence + confidence on every assignment, reproducible (§6.7) |
| Bulk label | Filter, then "Label", as one server call with a preview count |
| Filters | One typed language (OQL) shared by UI, API, groups and policies; faceted menu with counts that honour data scope (§6.5–6.6) |
| Groups | Static + dynamic, both scannable, resolved at dispatch through the ownership gate and exclusions; per-group cadence; RBAC sharing only, no public links (§6.12) |
| Exclusions | Discovery + dispatch + graph cut; matched inventory archived with a reason and restored on removal; approval workflow; scoped global / scope target / group (§6.13) |
| Policies | AND/OR/NOT; no hard delete (archive); preview required; caps, depth limit, circuit breaker; scan action behind approval and budgets (§6.15) |
| Change | Typed observation diffs per facet, cert expiry, tech version changes, rollups (§6.16–6.17) |
| Hosting | Self-hosted by default |

### 4.1 Design practices adopted

Sources: research 08, "asset inventory / exposure graph system design", and
research 09, "multi-type asset inventory" (2026-10-03). Each row says where
the practice lands in this RFC.

| # | Practice | Where it lands here |
|---|---|---|
| I1 | **Three layers.** Per-source records, then a correlation link, then a canonical asset whose "preferred" fields are recomputed from its linked records. Queries can target either the canonical view or one source | §6.4.5. OpenCTEM already has the per-source layer: `asset_sources.contributed_data` (`000014_data_sources.up.sql:52-69`) and RFC-003 source priority (`api/internal/app/ingest/priority_gate.go`). This RFC adds `service_sources`, an `asset_links` view of correlation decisions, the preferred-field recompute, and an OQL `source:` scope |
| I2 | **Deterministic identity keys in a fixed order** (MAC, then IP within a time window, then hostname). A manual merge exists as the fallback | RFC-028 already matches strong id → name → windowed hostname → windowed IP and never auto-merges. §6.4.5 adds a **split** action with audit, next to merge |
| I3 | **Correlation is a scheduled, single-flight batch job** after ingest, followed by a history snapshot | §6.4.5. Ingest keeps an inline strong-key match, because findings need an asset id immediately. A single-flight job per tenant and zone runs the windowed matches, recomputes preferred fields and writes the rollup snapshot (D15) |
| I4 | **Correlation never crosses a hard network boundary** | §6.4.5. Identity keys for private addresses include the scan zone (D16). Public addresses correlate tenant-wide. The tenant is always a hard boundary |
| I5 | **Change detection without full event sourcing.** Rows carry a run tag and `first_seen`. Stale rows are cleaned up only within the scope that was synced. Assets a scan missed are marked offline, never deleted | §6.16. `last_seen_run_id` on assets, services and source records. "Closed" and "offline" are evaluated only for the targets and zone the run covered. Attribute-level diffs come from the observation hashes, which run tags alone do not give |
| I6 | **Connectors are get → transform → load → scoped cleanup**, with retries in the framework; cleanup never runs after a failed fetch | §6.9. A connector interface for RFC-036 P5 cloud sources and imports |
| I7 | **Rules + Facts with mandatory `identity_fields`.** A generated issue keeps a stable identity across runs | §6.15.2. Every policy effect, digest and any future exposure-raising action declares identity fields: `(policy_id, subject_id[, port])`, never volatile values |
| I8 | **A field/operator/value query grammar** with typed operators, exact vs fuzzy matching, a non-empty test, and **grouping so that several conditions must match the same nested service** | §6.5. OQL adds `=` exact vs `:` fuzzy, `field:*` non-empty, and `services:( … )` same-service grouping compiled to one `EXISTS`. A regex operator is deliberately **not** offered (ReDoS, T8) |
| I9 | **Five attribution states** (approved, dependency, monitor only, candidate, requires investigation). Ownership and discovery confidence are better stored as two fields | RFC-036 states, and #835 stores `state` and `confidence` separately. OQL exposes both (`attribution`, `attribution.confidence`) |
| I10 | **Two-level taxonomy.** An abstract class (Host, Domain, CodeRepo, User …) sits above a source-specific type. Lists and queries work at class level across connectors | §6.3.2: 16 classes + `other` in `assets.asset_class` above the 37 types, grouped into 8 lenses; each class records its JupiterOne `_class` equivalent for interoperability (registry field `jupiterone`). The source-native type is kept on the source record. `DnsRecord` and `Image` wait for matching types |
| I11 | **EASM kinds are a subset of the full model.** Domain, IpAddress, Certificate, Port and ApplicationEndpoint sit next to Cluster, Function, CodeRepo, User and NHI | §6.3: the service list is one lens. External surface is one class of the shared model, not a separate inventory |
| I12 | **A common core plus per-class schemas**, not a table per type and not table inheritance. OCSF keeps device kind as one `type_id` enum on one object | D19 (a): one `assets` table with core columns and one versioned JSON Schema per type, validated in Go on write. OCSF does **not** endorse an untyped bag; that claim was refuted 0-3 |
| I13 | **OCSF `resource_details`** gives shared field names: owner, criticality, labels, tags, type, group, region, created/modified, relationships | §6.3.4. The core field names map to OCSF in the SIEM and CTIS exports |
| I14 | **jsonb, a GIN `jsonb_path_ops` index for containment, and expression indexes for the hot per-type keys.** Facets that are used everywhere or need sorting should be real columns, because planner statistics on jsonb keys are weak (PostgreSQL docs) | §6.3.3: core facets are columns; per-type facets get generated partial expression indexes; a `jsonb_path_ops` GIN on `properties` serves ad-hoc `@>` containment. This replaces the default `jsonb_ops` GIN of `000008:129` once measured |
| I15 | **No flat "everything" list.** Separate views per entity class, with services and certificates first-class and linked to a parent asset; an "All" view plus per-category tabs, each with its own default columns | §6.3.6 lenses: All assets plus class lenses. Services and certificates are sub-views of External surface |
| I16 | **Two-layer filters.** Common filters apply to every kind; per-kind filters appear for that kind | §6.3.3. Core facets always show; registry facets appear once a lens, class or type is selected |
| I17 | **Ownership state is independent of type.** Only approved assets show by default, count in dashboards and get the daily cadence; candidates are hidden until the state filter is cleared | RFC-036 states (#835). The default inventory view shows `attribution` confirmed or legacy, with a banner linking to the needs-review count (D21) |

**Our own design inference, not verified practice:** the "attack surface
to code" relationship chain (§6.3.5, the typed path and its edge sources,
built from a graph model and OCSF `resource_relationship`) and connector
normalisation.

**What research 08 did not verify.** It has no verified evidence on:

- storage engines: Postgres JSONB/GIN, materialised facet tables,
  ClickHouse, OpenSearch, or a graph database;
- multi-tenant storage isolation;
- retention and its cost.

So these choices in this RFC are **our own reasoning**, not external
evidence:

- Postgres with typed columns and per-tenant snapshot tables (§6.4.3,
  §6.6);
- the 100k/1M performance targets (§7);
- the retention periods, beyond RFC-036 O7;
- revisiting a search engine only above 5M services per tenant (§11).

The P0 performance tests are what validate them.

## 5. Trust and threat model

Assets and services carry **attacker-controlled text**: page titles,
banners, headers, certificate subjects, favicons, redirect targets, DNS
names and screenshots of arbitrary pages. Tenants are mutually distrusting.
Policy authors are trusted with their tenant's inventory, but not with
unbounded side effects.

| # | Threat | Vector | Control | Test |
|---|---|---|---|---|
| T1 | Stored XSS via titles, banners, headers, certificate fields | A target serves `<title><img src=x onerror=…>` | Stored as text, capped (title 512, banner 4,096, header value 1,024), C0/C1 controls stripped at ingest. The web renders them as React text only; `dangerouslySetInnerHTML` is banned for inventory fields by a lint rule. OQL highlighting escapes before markup | Ingest fixture with hostile titles; Playwright asserts no script runs on list, card, drawer or export |
| T2 | XSS or content sniffing via the screenshot or favicon bytes | Polyglot PNG/HTML, SVG favicon | The API decodes every image and **re-encodes** to WebP; it never stores or serves the sensor's original bytes. SVG is never accepted. Response: `Content-Type: image/webp`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `Cross-Origin-Resource-Policy: same-origin`, `Content-Disposition: inline; filename="screenshot.webp"` | Polyglot and SVG fixtures rejected; header assertions |
| T3 | SSRF through the headless browser | Page redirects or loads `http://169.254.169.254/`, `file://`, internal names; DNS rebinding | The browser runs on the **sensor**, never on the API. Top-level navigation is pinned to the scanned address (`--host-resolver-rules` maps the host to the observed IP). Subresource requests to loopback, link-local, RFC 1918, ULA and metadata ranges are refused by a request interceptor **unless** the scan zone is internal and the address is in scope. Non-HTTP(S) schemes, downloads, service workers, WebRTC, notifications and geolocation are off. Fresh profile per capture | Fixture page that redirects to metadata and loads `file://`: both blocked, logged |
| T4 | Browser escape or resource exhaustion | Malicious JS, memory bombs, infinite redirects | Chromium sandbox **on** (no `--no-sandbox`), non-root, seccomp, separate process group with a memory cap (512 MB) and CPU time limit. Hard timeout 20 s per capture, 10 redirects max, one tab, no persistent storage. Capture is skipped for responses over 5 MB HTML | Fuzz pages; the sensor survives and reports `capture_failed:timeout` |
| T5 | CSV / spreadsheet formula injection | Title `=HYPERLINK(...)` exported | Exports prefix cells starting with `= + - @ \t \r` with `'` (OWASP) | Export fixture |
| T6 | Notification injection | Title with Slack mrkdwn or Teams markup in an alert | Notifier escapes per channel; inventory values are sent as quoted text with a length cap | Unit tests per channel |
| T7 | Cross-tenant data in facets, groups, exports | Missing `tenant_id` predicate; shared materialised counts; cache keys | Every compiled query starts from `tenant_id = $1` added by the compiler, not the caller. Materialised facet rows are keyed by tenant. Data scope is applied to list, facets, groups, exports and previews (fixes F10). Out-of-scope ids return 404. Cache keys include tenant and data-scope hash | Two-tenant integration test per endpoint; a scoped user's facet totals equal their list total |
| T8 | OQL injection | `q=port:443) OR (1=1` or a field name crafted as SQL | Parsed to an AST by a hand-written parser. Fields resolve **only** through the registry to fixed SQL fragments; values are always bind parameters. No raw SQL, no regex operator (ReDoS); wildcards compile to `LIKE` with escaping. Limits: 2,000 chars, 64 clauses, depth 8, 50 list values | Fuzz the parser (Go native fuzzing); golden tests on emitted SQL |
| T9 | Expensive queries as DoS | Leading-wildcard search on 1M rows; many facets | `statement_timeout` per endpoint (list 3 s, facets 1.5 s per field, preview 5 s); a lower-bound result on timeout instead of an error where safe; per-user rate limit on facets and exports | Load test (§7) |
| T10 | Policy abuse: mass archive | Broad condition plus `archive`, or a typo in a condition | Preview required before enable; per-run caps (archive ≤ 100 or 5 % of the subject set, whichever is smaller); over the cap → run pauses as `needs_confirmation`; archive is reversible; full audit | Policy matching all rows pauses with zero changes |
| T11 | Policy abuse: scan storms and loops | `on_change` + `trigger_scan`, or label ping-pong between two policies | Scan action needs `scans:execute` held by the author **at run time**, goes through the target gate and the tenant's scan budget, at most one scan per policy per hour by default, and is created `pending_approval` unless the policy was approved by a second person. Changes made by a policy carry `origin = policy:<id>`; a policy never fires on its own changes; chain depth ≤ 3; three capped runs in a row disable the policy and notify its owner | Two mutually-triggering policies stop at depth 3; loop test |
| T12 | Exclusion bypass | Hostname resolving into an excluded CIDR; alias names; pipeline hops | The gate matches name, aliases, resolved addresses and lineage ancestors; it runs at trigger, claim and every pipeline hop (§6.11) | Gate test matrix |
| T13 | Label or policy spoofing via scanner output | A sensor report sets `labels` or `system_labels` | System labels are written only by the label engine on the API; ingest drops reserved keys (pattern already used for properties, `processor_reserved_props_test.go`) | Hostile report fixture |
| T14 | Information leak through screenshots | Screenshot of an internal admin page shown to a user without access | Screenshot reads use the service's authz and data scope; no public or signed URLs; retention 30 days | Scoped-user test |

## 6. Design

### 6.1 Principles

1. **Typed columns for what people filter on; JSONB only for the long
   tail.** You cannot facet 100k rows fast over `jsonb_object_keys`.
2. **One compiler, one gate.** There is one OQL compiler and one target
   gate. Every consumer calls them; none re-implements them.
3. **Change-only history.** Observations grow with change, not with scan
   count (RFC-036 §6.5).
4. **Reversible automation.** Policies and exclusions archive and label;
   they never hard-delete. Every automated change records its origin.
5. **Honest numbers.** Every count states whether it is exact, a lower
   bound, or from a snapshot (`as_of`). Empty inputs give
   `"status": "insufficient_data"`.
6. **Reuse the registers.** Assets, relationships, state history, exposure
   events, findings, the outbox, the audit log, `FileStorage`, scope
   exclusions and the approval flow are reused. A new table is added only
   when there is nowhere existing to put the data.

### 6.2 Entities

```
seed (RFC-036) ──lineage──► asset (identity, owner, criticality, attribution, labels)
                               │ 1..n
                               ▼
                            service = host:port/transport (HTTP, TLS, net, tech, labels, screenshot)
                               │ 0..n                         │ 0..n
                               ▼                              ▼
                     observation (facet, hash, value,     finding (service_id nullable)
                     first_seen, last_seen, run)
```

- **Asset:** unchanged identity (RFC-028). It gains `apex_domain` (eTLD+1
  from the public suffix list), DNS columns (§6.4.2) and `system_labels`.
- **Service:** the browsing unit of the **External surface** lens, one row
  per `(host asset, port, transport)`. Other classes browse assets
  directly (§6.3.6). A host asset is a domain, subdomain or IP address. A virtual
  host on a shared IP is a service of the *hostname* asset, with `ip`
  recorded, so `a.example.com:443` and `b.example.com:443` on one IP are
  two rows, which is what people expect.
- **Observation:** one facet value seen for an asset or service over a
  time span.
- **Label:** a named tag on an asset or service, either system (from a
  rule) or custom.
- **Technology:** a catalog entry (name, categories, description, icon),
  plus per-service detections with a version.

### 6.3 Asset classes and the type registry

OpenCTEM is **not** only a web-services inventory. OpenCTEM has 37 asset types
(`AllAssetTypes()`, `api/pkg/domain/asset/value_objects.go:126-182`), and
the live demo tenant uses 21 of them. Repositories are the most common
type there, followed by hosts, networks, IPs, subdomains, domains and
services. So the service card is **one lens** (the external
surface) and not the shape of the whole inventory. This section defines
what every type shares, what differs per type, and the one place where
those differences are declared.

#### 6.3.1 Today: four taxonomies that disagree (F24)

| Where | What it says |
|---|---|
| Go `api/pkg/domain/asset/category.go:7-77` | 9 categories, "derived — NOT stored": external_surface, application, infrastructure, network, cloud, data, code, identity, other. Database and container are infrastructure; service, http_service and open_port are network |
| DB `asset_type_categories` (`000037_asset_types.up.sql:91-99`, `000060_schema_fixes.up.sql:64-66`) | 8 codes: infrastructure, application, code, cloud, data, identity, other, recon. There is **no** external_surface and **no** network |
| Web `web/src/features/assets/lib/category-templates.tsx:6-16` | 7 groups: External, Applications (includes `service`), Cloud, Infrastructure (includes database, network, VPC, Kubernetes), Code, Identity, Recon |
| `api/configs/relationship-types.yaml:39-49` | Constraints name "virtual frontend types" (`k8s_workload`, `container_image`, `api_endpoint` …) that are not real types, so the backend cannot enforce them |

On top of this, each of the 25 typed pages under
`web/src/app/(dashboard)/(discovery)/assets/*/config.tsx` hand-codes its
own columns, form fields and detail sections against loose
`metadata.*` keys. `hosts/config.tsx`, for example, reads both
`metadata.ip` and `metadata.ip_addresses`. A new type therefore means
scattered page code, and the same type is grouped differently on
different screens.

#### 6.3.2 Classes above the types, lenses above the classes

The taxonomy has three levels, each with one job:

| Level | Cardinality | Job | Example |
|---|---|---|---|
| **source-native type** | unbounded | provenance only, on the source record (`asset_sources.native_type`) | `aws_instance`, `github_repo` |
| **type** (`asset_type`) | 37 today | the normalised OpenCTEM type; drives the attribute schema, renderers, identity keys | `host`, `repository` |
| **class** (`asset_class`) | 16 + `other` | the abstract kind (I10); used by cross-type queries, relationships and policies | `Host`, `CodeRepo` |
| **lens** | 8 + All | a fixed group of classes for the UI tabs (I15) | External surface, Code |

Each type has exactly one class, and each class belongs to exactly one
lens. Exposure is orthogonal: an internal host is still a `host`, and a
public bucket is still a `data_store`.

Each class records its JupiterOne `_class` equivalent for interoperability
(registry field `jupiterone`). OCSF is the reference for the shared core fields (I13).

| Class (`asset_class`) | Interop `_class` (`jupiterone`) | OpenCTEM types | Lens |
|---|---|---|---|
| `domain` | Domain / DomainRecord | domain, subdomain | External surface |
| `ip_address` | IpAddress | ip_address | External surface |
| `certificate` | Certificate | certificate | External surface |
| `service` | Port / NetworkEndpoint | service (generic); **service rows** (§6.4); legacy `open_port`, `http_service` | External surface |
| `web_endpoint` | ApplicationEndpoint | discovered_url | External surface |
| `application` | Application | application, website, web_application, api, mobile_app | Applications |
| `host` | Host / Device | host, compute, endpoint | Cloud & infrastructure |
| `function` | Function | serverless | Cloud & infrastructure |
| `cloud_account` | Account | cloud_account | Cloud & infrastructure |
| `container` | Container / Workload | container | Containers & Kubernetes |
| `cluster` | Cluster | kubernetes, kubernetes_cluster, kubernetes_namespace | Containers & Kubernetes |
| `artifact_registry` | Repository (artifact) | container_registry | Containers & Kubernetes |
| `code_repo` | CodeRepo | repository (components/SBOM stay in `asset_components`) | Code |
| `identity` | User / AccessRole / NHI | identity, iam_user, iam_role, service_account | Identities |
| `data_store` | DataStore / Database | database, data_store, storage, s3_bucket (alias) | Data |
| `network` | Network / Firewall / Gateway | network, vpc, subnet, firewall, load_balancer | Network |
| `other` | — | unclassified | All assets only |

**Gaps against research 09's suggested list.** It suggests `DnsRecord`
and `Image` classes. OpenCTEM has no DNS-record or container-image
*type* today: DNS records are columns and observations of a `domain`
(§6.4.2), and images are scanned through containers and registries.
Adding either is a registry change: a new type plus a class row, with no
migration beyond the seed. That is the point of the registry.

The **External surface** lens holds 5 of the 16 classes. EASM output is a
subset of the shared model (I11), not a separate inventory.

Classes and lenses are **fixed in code**, not tenant-editable (D18).
Tenants organise with groups and labels instead. This follows the owner's
taxonomy decision that type, group and tag are all needed and do
different jobs.

In OQL, `class:` and `lens:` are core fields: `lens:external_surface`,
`class:code_repo`, `type:repository`.

#### 6.3.3 The type registry (one definition, generated everywhere)

The registry follows the pattern that already works for relationships
(`api/configs/relationship-types.yaml` → `make generate-relationships` →
Go constants + `web/src/features/assets/types/relationship.types.generated.ts`).

- **Source of truth:** `api/configs/asset-types.yaml`, from which
  `make generate-asset-types` emits Go and TypeScript.
- **Served at runtime:** `GET /api/v1/asset-types`, versioned with an
  ETag. The web builds every inventory view from this response.
- **Generated TS types:** the web also gets generated TypeScript types
  for compile-time checks.

One entry per type:

```yaml
- type: repository
  class: code_repo                    # lens follows from the class (Code)
  label: Repository
  plural: Repositories
  icon: git-branch                     # name from a closed icon set in web
  sub_types: [github, gitlab, bitbucket, azure_devops]
  identity_keys: [provider_repo_id, canonical_url]   # RFC-028 identifier kinds, in match order
  storage: extension                   # core + asset_repositories (exists, 000009)
  attributes:                          # typed per-type schema (JSON Schema subset, as RFC-038)
    provider:       { type: enum, values: [github, gitlab, bitbucket, azure_devops], facet: true, group: true }
    visibility:     { type: enum, values: [public, private, internal], facet: true }
    language:       { type: string, facet: true, group: true }
    default_branch: { type: string }
    last_commit_at: { type: time }
    archived:       { type: bool, facet: true }
  columns: [name, provider, visibility, language, findings.open, last_commit_at, owner]
  card: repository                     # renderer key from the web's closed set
  sections: [overview, findings, components, secrets, branches, relationships, owners, sources, history]
  relationships:
    out: [deployed_to: [container, kubernetes, compute, serverless]]
    in:  [contains: [application]]
  scannable_by: [semgrep, trivy, betterleaks]
```

Each entry declares:

- **Class:** §6.3.2 (the lens follows from the class).
- **Attributes:** a typed schema per type. It is validated on every
  write: ingest, `POST/PATCH /assets` and import. Unknown keys are kept,
  but only in a quarantined `properties.x_*` namespace, never promoted.
- **Facets and group-by:** attributes marked `facet`/`group` become OQL
  fields named `<type>.<attr>`, for example `repository.provider`. The
  short form `provider` is accepted when it is unambiguous inside the
  query's class. The OQL field registry (§6.5.2) is **generated** from
  the core fields plus these.
- **Row and card renderer:** `columns` and `card` name renderers from a
  closed set in the web (`tech_chips`, `tls_expiry`, `status_chip`,
  `repo_provider`, `cloud_region` …). The API ships names, never markup
  or code.
- **Detail sections:** an ordered list of section keys, from the same
  closed set.
- **Allowed relationships:** constraints referencing
  `relationship-types.yaml`. Codegen resolves that file's virtual types to
  real `type` + `sub_type` pairs, so the constraints become
  **server-enforced** and lose the "advisory only" limitation noted in
  that file.
- **Identity keys:** the ordered RFC-028 identifier kinds the correlation
  job (§6.4.5) uses for this type. Examples:

  | Type | Identity keys, in order |
  |---|---|
  | host | sensor_id, cloud_instance_id, mac, ip@zone (3 d window), fqdn |
  | certificate | sha256 fingerprint |
  | iam_user | provider principal id, ARN |
  | domain | fqdn |

- **Scanners:** `scannable_by` tells the target gate (§6.11) which tools
  accept the type. This replaces the hard-coded type filter at
  `trigger.go:1139-1199`.

**Where attributes are stored** (D19, our reasoning):

- The **unified core** (§6.3.4) is real columns on `assets`.
- **Per-type attributes** live in `assets.properties` JSONB, validated by
  the registry schema.
- Every attribute marked `facet` gets a **partial expression index**:
  `CREATE INDEX … ((properties->>'provider')) WHERE asset_type =
  'repository'`. Codegen emits these into a migration.
- **Extension tables** are used only for one-to-many or high-volume
  structured data: `asset_services` (§6.4), `asset_components`, and the
  existing `asset_repositories`.

The trade-off: one extension table per type would mean 37 tables, a join
per type, and a migration for every new attribute. Untyped JSONB, the
state today, has no validation and no index. Schema-validated JSONB with
generated partial indexes gives typed facets per type, at the cost of one
small index per facet attribute. Extension tables stay where the data is
not one row per asset.

**The database follows the registry.**

- `asset_types` gains a `class` column. It is re-seeded from the YAML by
  a migration each time the registry changes, and the CI check
  `asset-types-drift` fails on a mismatch.
- `asset_type_categories` is kept read-only for one release, then
  dropped.
- `category.go`'s map and `category-templates.tsx` are replaced by
  generated code.
- `assets.asset_class` (and `assets.asset_lens`) are denormalised columns, set from the type by
  the same trigger that validates `asset_type`, and indexed. Cross-type
  facets and lenses filter on it without a join.

#### 6.3.4 The unified core (every type)

Every asset row has these, and cross-type search, facets, sort, group-by
and policies run over them:

| Core field | Source |
|---|---|
| `name`, `type`, `sub_type`, `class`, `lens` | `assets` |
| `owner` (unified, api#520), `bu`, `business_service` | existing |
| `criticality` and **`effective_criticality`** (MAX of asset, BU, business service, served control plane; §3.5) | existing, read time |
| `attribution` state + `attribution.confidence` (RFC-036, #835) | `asset_attributions` |
| `exposure`, `is.public` | existing |
| `labels` (custom `tags` ∪ `system_labels`) | §6.7 |
| `first_seen`, `last_seen`, `last_seen_run_id`, `state` | existing + §6.16 |
| `sources` (count, and `source:` scope) | `asset_sources` (§6.4.5) |
| `findings.open`, `findings.max_severity` | counters, as on services (§6.4.4) |
| `groups` | static membership or dynamic expansion |

Class-specific facets come from the registry (§6.3.3). The **All assets**
lens shows the core columns plus one type-aware cell, the type's `card`
renderer in compact form. A mixed list of repositories, hosts and IPs
therefore stays readable without a column per type.

#### 6.3.5 The typed relationship graph: attack surface to code

The existing `asset_relationships` table and its relationship types carry
the graph. This RFC adds what is needed to walk from the internet to the
code:

```
domain ─contains→ subdomain ─resolves_to→ ip_address ─exposes→ [service row 443/tcp]
   [service row] ─serves→ web_application ←serves_certificate─ certificate
   web_application ─runs_on→ load_balancer? ─load_balances→ kubernetes (workload) ─contains→ container
   repository ─deployed_to→ container            (the image's source repository)
```

- **Edges are still asset-to-asset.** `asset_relationships` gains a
  nullable `service_id` qualifier, so that "web_application X is served on
  `host:443`" points at the exact service row. It joins the merge plan.
- **New relationship types** in `relationship-types.yaml`: `serves`
  (service host → application, qualified by `service_id`) and
  `serves_certificate` (RFC-036 §6.5). `hosted_by` and `cname_of` come
  from RFC-036; `deployed_to`, `runs_on`, `load_balances` and `contains`
  already exist.
- **Where the edges come from:**
  - discovery: resolve, CNAME and TLS for the external chain;
  - cloud and Kubernetes connectors: load balancer → workload →
    container;
  - container scans: trivy image metadata `org.opencontainers.image.source`
    → repository, matched on the repository's `canonical_url` identity
    key;
  - manual edges.
- **The path query.** `GET /api/v1/assets/{asset_id}/paths?to_class=code_repo&max_depth=8`
  is a recursive CTE.
  - It follows only the relationship types the registry marks
    `traversable`.
  - It is cycle-safe, and applies tenant and data scope at every hop.
  - It returns each path with its edges and the open findings at each
    node.
  - The drawer of an exposed service shows "runs code from `repo-x`
    (3 critical findings)". The reverse view, on a repository, shows
    "reachable from the internet through `api.acme.com:443`".
- **What this feeds.** It is the input RFC-017 reachability and
  attack-path work need. An inventory that stops at the web service cannot
  answer it.

#### 6.3.6 Lenses

A **lens** is a registry-defined preset:

- the classes it covers (or an OQL base query);
- its default columns or card;
- its default facets and group-by.

Lenses are served with the registry from `GET /api/v1/asset-types`.

| Lens | Base | Row | Default group-by |
|---|---|---|---|
| All assets | none | core columns + compact type cell | lens, then class |
| External surface | `lens:external_surface OR is.public:true`; subject = services for the card view, with Domains, IPs and Certificates sub-views | service card (§6.19) | tech / port / domain |
| Applications & APIs | `lens:applications` | app card (URL, auth, tech, findings) | type |
| Cloud & infrastructure | `lens:cloud_infra` | provider, account, region, OS, public IP | cloud_account |
| Containers & Kubernetes | `lens:containers_k8s` | cluster, namespace, image, registry | cluster |
| Code | `lens:code` | provider, visibility, language, findings by scanner, last commit | provider |
| Identities | `lens:identities` | provider, privileged, MFA, last used | type |
| Data | `lens:data` | engine, public, encryption | type |
| Network | `lens:network` | CIDR, VPC, zone | vpc |

Every lens keeps the same machinery:

- OQL filter bar and server facets;
- group-by with per-group paging, export and scan;
- bulk label and status;
- saved views (`saved_filters` gains `lens`);
- dynamic groups.

**URLs.** The 25 typed pages become lens presets
(`/assets/hosts` → `/assets?lens=cloud_infra&q=type:host`). The old URLs
keep working through 308 redirects, following the
`web/src/config/legacy-routes.ts` pattern.

**Reserved `/assets/*` page segments.** These static pages sit next to
`/assets/[id]` and are not lenses: `all`, `changes`, `duplicates`,
`groups` (asset groups, static and dynamic, §6.12), `services` and
`suggestions` (relationship suggestions). No lens, class or type id may
take one of these names; `cmd/gen-asset-types` rejects the registry if
one does. The Assets tabs (§6.19) all live in the web under `/assets`
(`/assets/groups`, `/assets/changes`, `/assets/suggestions`), because a
URL mirrors its place in the nav. The APIs keep their top-level
resources, `/api/v1/asset-groups` and `/api/v1/relationships` (RFC-041;
`/api/v1/assets/groups` would collide with `/assets/{asset_id}`).

#### 6.3.7 How existing things map in (nothing breaks)

| Existing | v2 |
|---|---|
| 37 types, `sub_type`, `TypeAliases` (`value_objects.go:88-113`) | The registry lists them with their sub-types and aliases. **Amended by §6.3.8:** aliases are input names only and are never stored; sub-types are a closed list per type |
| Owner decision: type / group / tag are all needed | Kept. Type = registry; group = static and dynamic groups (§6.12); tag = custom labels (§6.7) |
| Owner decision: effective criticality = MAX(asset, BU, service), used by risk score and priority | Unchanged, exposed as the core field `effective_criticality`; policies set only the asset's own value |
| `asset_types` / `asset_type_categories` tables | `asset_types.class` added and seeded from the YAML; categories table retired after one release |
| `category.go`, `category-templates.tsx` | Replaced by generated code; the category names map to lenses, except `recon`, which folds into the External surface lens, and `infrastructure`, which splits into the Cloud & infrastructure and Containers & Kubernetes lenses. Classes are finer than any of the old category lists (16 + other) |
| 25 per-type `config.tsx` pages | Folded into registry entries one class at a time; custom cells become named renderers; URLs redirect to lenses |
| `relationship-types.yaml` virtual types | Resolved to real types by codegen; constraints enforced on the server |
| Type compatibility filter in `trigger.go` | `scannable_by` from the registry |

#### 6.3.8 Type model hardening (amendment, 2026-10-03)

> Status: **Accepted.** The owner approved O1–O6 as recommended on
> 2026-10-03. The evidence is the asset-types review of the same date
> (research 13: necessity, completeness, quality and best practice of the
> asset types, with every HIGH finding re-read in code). This section
> records the rules, the decisions and the ordered PR plan T0–T8.
> Implementation status is kept in the table in "The plan" below.

**Why.** The set of classes and core types is about right: 16 classes and
17 core types. What is wrong is that
the registry is **not yet the source of truth**:

- **Alias types are stored.** `ParseAssetType` accepts all 38 names, so
  `POST /assets`, CSV import and the seeds store `website`, `api`,
  `kubernetes_cluster` and the like verbatim. Only ingest resolves aliases.
- **Type-aware features compare against names that are never stored**,
  so they silently do nothing (the "silently inert" class):
  - exposure inference never marks websites and APIs public;
  - 30 of 98 threat-model applicability rows are keyed by alias names;
  - the asset-group `website_count` and `credential_count` are always 0;
  - the scanner/target mappings know only alias names for url, kubernetes,
    mobile and api, so every `application` is reported as skipped by ZAP
    and the nuclei url target; the filter is advisory, so the UI reports
    skips that never happen;
  - relationship constraints resolve to alias names, which breaks the
    Add-relationship dialog for `application`, `identity`, `kubernetes`,
    `certificate` and `endpoint` assets.
- **Sub-types are free text** with three meanings mixed: kind (`cluster`,
  `iam_role`), vendor (`aws`, `github`) and engine (`postgresql`). Nothing
  validates them, and the typed web pages never send one, so an asset
  created on the Websites page disappears from that page.
- **The registry's identity keys and attribute schemas are read by no
  code.** Identity families and scanner compatibility are hard-coded.
- **14 legacy `asset_types` rows** (`ip`, `ip_range`, `port`,
  `code_artifact`, `container_image`, `cloud_resource`,
  `serverless_function`, `user_account`, `credential`, `ssl_certificate`,
  `iot_device`, `hardware`, `other`, `server`) are not in the registry but
  are still valid foreign-key targets and are offered by the web.

##### Rules

These follow from D18/D19 and the evidence; they need no further
decision.

| # | Rule | How it is enforced |
|---|---|---|
| R1 | **Aliases are input names only.** An alias (`website`, `iam_user`, `s3_bucket` …) is accepted on every write path and resolved to (core type, sub_type) at the boundary. Only core types are stored. Feature code never compares against an alias | Generated `ResolveInputType` on every writer; the entity refuses a non-core type; `CHECK (asset_type IN (<core>))` on `assets` after the data cleanup (T3); a test fails on alias names in feature code |
| R2 | **Sub-type = kind, from a closed list per core type.** A vendor goes to `assets.provider` or the `provider` attribute, an engine or OS to an attribute. Legacy sub-type values are accepted on input and mapped (`postgresql` → `relational` + `engine: postgresql`, `aws` → no sub-type + `provider: aws`) | `sub_types` + `sub_type_inputs` in the YAML; REST, CSV and bulk reject an unknown sub-type with a validation error; ingest keeps it in `properties.x_native_sub_type` with a warning, so a sensor is never refused for it |
| R3 | **Every class is reachable through a core type of its own**, and an alias resolves within its own class | Generator check (from T4a, when `function`, `artifact_registry` and `web_endpoint` become core types) |
| R4 | **No type without a producer.** A type or sub-type enters the registry when a parser, connector or committed RFC produces it. Everything else is an attribute, a relationship, an `asset_components` row or a separate entity | Review rule for registry PRs |
| R5 | **Behaviour is declared, not coded:** `scannable_by`, `exposure_default`, identity family, hardware identifiers, relationship constraints | Generated from the YAML; read by ingest, the scan target gate and the relationship service |
| R6 | **The registry is the only list of types.** Go, TypeScript, SQL seeds and option lists are generated or read from it | `make asset-types-check` (CI "Asset Types Drift") |

`scannable_by` names **target types**, the vocabulary of a tool's
`supported_targets` (`url`, `domain`, `ip`, `host`, `repository`, …), not
tool names as the §6.3.3 example shows. Tools are tenant-addable, and a
custom tool declares target types, never a list of asset types.

##### Owner decisions (approved 2026-10-03)

| # | Question | Decision |
|---|---|---|
| **O1** | Should `subdomain` stay a stored type? | **No.** It is stored as `(domain, subdomain)`; apex vs subdomain is derived from the public suffix list at write time; `subdomain` stays an input alias, so sensors and CTIS do not change |
| **O2** | `network`: one type or two? | **One `network` type** with a closed sub-type list in two families, segments (`vpc`, `subnet`, `ip_block`, `vlan`, `security_group`) and devices (`firewall`, `router`, `switch`, `load_balancer`, `vpn_gateway`, `wireless_controller`, `access_point`, `ids_ips`), and per-sub-type identity flags (hardware identifiers only for devices). A `network_device` type is revisited when an OT or network-device connector lands |
| **O3** | The canonical web sub-type | **`website`** is the stored code, labelled "Web application". `web_application` becomes an input alias of `(application, website)` |
| **O4** | Secrets as assets | **A `secret` type** holding the per-tenant HMAC (#849) + metadata + locations, never the value; read gated by `findings:read` + data scope; never exported. P2 |
| **O5** | AI assets | **One core type `ai`** (`model`, `agent`, `mcp_server`) in a new class `ai`, shown in the Applications lens, **only once a producer exists** (exposed MCP/Ollama detection or a cloud AI connector). Vector stores are `database/vector` either way |
| **O6** | Scanner/asset type compatibility | **Enforcing**, generated from the registry's `scannable_by`, **after T2** (T2 gives it correct (type, sub_type) keys; enforcing earlier would block every `application` from url scanners). Dispatch refuses an incompatible tool/type pair with a clear reason; an asset whose compatibility cannot be decided (unclassified, or a tool target type the registry does not know) is dispatched, so the check never blocks a valid scan |

##### Closed sub-type vocabulary (T1)

| Core type | Sub-types (kinds) | Legacy inputs accepted and mapped |
|---|---|---|
| `service` | `http`, `open_port`, `discovered_url` | `port` → `open_port` |
| `application` | `website`, `web_application`, `api`, `mobile_app` | — (`api_collection` removed: no producer) |
| `host` | `compute`, `serverless` | `server` → none; `linux`/`windows`/`macos`/`bsd` → none + `os_family`; `kubernetes_cluster` → `kubernetes/cluster` |
| `cloud_account` | `account`, `project`, `subscription`, `organization` | `aws`/`gcp`/`azure`/`digitalocean` → none + provider |
| `container` | `image` | Kubernetes workload kinds (`deployment`, `statefulset`, …) → `kubernetes/workload` + `workload_kind` |
| `kubernetes` | `cluster`, `namespace`, `workload` | — |
| `repository` | none | `github`/`gitlab`/`bitbucket`/`azure_devops` → none + provider |
| `identity` | `iam_user`, `iam_role`, `service_account`, `identity_provider` | — (`credential` removed: a secret, O4) |
| `database` | `relational`, `document`, `key_value`, `graph`, `warehouse`, `vector` | engines (`postgresql`, `mysql`, `mongodb`, `redis`, …) → kind + `engine`; `data_store` → none |
| `storage` | `bucket`, `file_share`, `disk`, `container_registry` | `s3_bucket`, `s3` → `bucket` + provider `aws` |
| `network` | the O2 list | `wireless_ap` → `access_point`; `ids`, `ips` → `ids_ips`; `core_switch`, `access_switch` → `switch` |
| `ip_address`, `certificate` | none | `ip`, `ssl`, `tls` → none |
| `domain`, `subdomain`, `endpoint`, `unclassified` | none (O1 adds `domain/subdomain` in T4a) | — |

`container_registry`, `serverless` and `discovered_url` stay sub-types
until T4a gives their classes core types of their own.

##### The plan (ordered PRs to `develop`)

Every PR carries tests; data-access changes get two-tenant tests, and
migrations are run up, down and up on a scratch Postgres 17 with seeded
legacy data (never on live).

| PR | Scope | Contents | Status |
|---|---|---|---|
| **T0** | docs | This section, the rfcs README row, `architecture/asset-inventory-v2.md`, `development/asset-type-registry.md` | this PR |
| **T1** Close the writers | api + web | `ResolveInputType` / `StoredAssetTypes` / closed sub-types generated from the YAML; `POST`/`PATCH /assets`, CSV import, the Nessus and Kubernetes importers, ingest, connectors and seeds resolve aliases and validate the sub-type; fix the `properties.type` override (a non-alias value overwrote the type); typed web pages send `sub_type`; the CTIS mapper reads `properties.kind` for `kubernetes` | #948 |
| **T2** Re-key consumers | api + web | Exposure inference from the registry's `exposure_default`; asset-group counters by class; scan coverage by (type, sub_type); threat-model applicability keyed by (type, sub_type) with a migration rewriting the alias rows; relationship constraints resolved to (core, sub_type) and enforced for human writes; scanner compatibility from `scannable_by` (advisory); assignment-rule type conditions resolved through the registry; web option lists from the registry; a test that fails on alias names in feature code. Each fix has a probe test that fails on `develop` before it | #978 |
| **T3** Normalise data | api migration | §6.3.8.1. Stored aliases → (core, sub_type); undeclared sub-types → the closed list or attributes; the 14 legacy codes → a stored pair with the code kept in `x_native_type`; delete the 14 legacy `asset_types` rows; `CHECK` on `assets.asset_type` (migration 000684). Dropping the unread `asset_types.module_id` is left to a later contract step | in review |
| **O6** Enforce compatibility | api | A single-scanner run leaves out the asset-group members whose stored (type, sub_type) its scanner's target types cannot scan (registry `scannable_by` plus active admin target mappings), records the count and a reason per type, and is refused with `NO_COMPATIBLE_TARGETS` (400) when nothing is left; every workflow step is gated again for its own tool when its sensor command is built (both step dispatchers), a step left with nothing fails with `INCOMPATIBLE_TARGETS` and never reaches a sensor. Undecidable assets (unclassified, a type the registry does not know, a tool without platform target types) are dispatched; direct targets typed by the tenant have no stored type and keep their existing checks | #992 |
| **T4a** Boundary fixes | api + registry + migration | `endpoint` → `(host, workstation)`; core types `function`, `artifact_registry`, `web_endpoint`; network identity flags (O2); `web_application` → `(application, website)` (O3); `subdomain` → `(domain, subdomain)` with the PSL-derived sub-type (O1) | O3 in review (migration 000685); `endpoint` → `(host, workstation)` in review (migration 000773); the rest next, one PR each |
| **T4b** `container_image` | api + registry + sensor + ctis/sdk-go | New core type and class `image`; trivy `container_image` → `container_image`; move `container/image` rows; identity = digest; `built_from`/`deployed_to` edges | next |
| **T5** Executable registry | api | Attribute validation and `x_*` quarantine on every write (warn-only on ingest for one release); identity family / hardware flags / `attr.*` keys read by the correlator (RFC-043 P3 #18); per-type `schema_version`; `x_native_type` kept on `unclassified` | next |
| **T6** Web from the registry | web | Delete the hand-written type maps, alias branches and slug maps; the asset-group add dialog reads the registry | with RFC-042 slice 6 |
| **T7** Interop | api + ctis | `ocsf` / `cyclonedx` fields per type; OCSF inventory export; CTIS enum parity test | after T5 |
| **T8** Gaps, each gated on a producer | api + sensor + connectors | `identity` `user`/`group`/`oauth_app` (Entra/Okta connector); `network/ip_block` producers; `domain` email-posture attributes; then O4 `secret`, O5 `ai`, `saas_tenant`, IoT/OT | after T5 |

Order: T1 → T2 → T3 → (O6) → T4a/T4b → T5; T6 follows slice 6; T7 and
T8 run in parallel after T5. The research-12 isolation fixes (S0) land
first; T1 touches the same `POST /assets` path.

###### 6.3.8.1 The normalisation migration (T3, reused by T4a)

1. **Ledger.** `asset_type_reclassifications` records, per moved asset
   and migration, the old (type, sub_type, provider) and the exact
   properties it added. It is written in the same transaction as each
   update (`asset_type_normalise_batch`). The down migration replays it
   for its own migration only: it restores an asset only while its type
   is still the one the migration set, removes a property only while it
   still has the migration's value, and leaves the append-only
   `reclassified` history rows.
2. **Mapping from the YAML.** The generated block seeds
   `asset_type_input_map` (old type, old sub-type → new type, new
   sub-type, provider, attributes) and each type's closed `sub_types`
   into `asset_types`. The only hand-written mapping is
   `asset_type_legacy_codes`, for the 14 codes that are not registry
   types (`ip` → `ip_address`, `server` → `host`, `credential` →
   `unclassified` …); a DB test checks that each target is a stored pair,
   and the code is kept in `properties.x_native_type`. An attribute or a
   provider that already has a value is never overwritten (a provider
   implied by a vendor sub-type that contradicts the asset's own provider
   is dropped and the sub-type kept as `x_native_sub_type`); an undeclared
   sub-type with no mapping moves to `properties.x_native_sub_type`.
3. **Batches** of 5,000 by id, idempotent and re-runnable; only rows
   whose (type, sub_type) need a change are touched; `updated_at` is not
   bumped; the class/lens trigger re-derives in the same update.
4. **Names are not touched**, so the unique `(tenant_id, name)` key
   cannot collide, and identifiers, findings, relationships, groups,
   owners and history keep the same `asset_id`.
5. **Dedup-aware, not dedup-acting.** Pairs that are now the same class
   in one tenant with the same host but different names (for example
   `https://app.x.com` and `app.x.com`) go to the RFC-043 review queue
   with reason `type_consolidation`. Nothing merges automatically.
6. **History.** One `reclassified` state-history row per moved asset
   (field `asset_type`, old → new).
7. **Legacy rows.** The 14 legacy `asset_types` rows are deleted only
   when no asset references them (the foreign key is `ON DELETE
   RESTRICT`, so a stray reference fails loudly); a snapshot table keeps
   them for the down migration. Alias rows stay (they carry `alias_of`
   for the classifier) and are marked `is_storable = false`.
8. **Constraint.** `chk_assets_core_type` is added `NOT VALID`, then
   validated (SHARE UPDATE EXCLUSIVE; writers keep running).
9. **Deploy.** `air` does not run migrations: deploy with an explicit
   migrate step.

#### 6.3.9 The property schema (amendment, 2026-10-07)

**Problem.** The owner, on a domain's Properties ("Ip 202.160.124.20",
"Ip addresses 202.160.124.20", "Port 443"): what are `ip` and
`ip_address`? One concept, an asset's addresses, was stored under six keys
(`ip`, `ip_address` as a string or an object, `ips`, `ip_addresses`,
`resolved_ips`, `addresses`), and each reader (correlation, scope
exclusions, relationship inference and suggestions, the IP lookups, scan
dispatch) kept its own subset of them. A port, a service's attribute,
landed on a domain: a nuclei result names the host it reached and adds the
port, and names are unique per tenant, so it merged into the domain.

**Design.**

1. *One property schema, in the registry.* `api/configs/asset-types.yaml`
   declares every property key once (`properties`): English and
   Vietnamese labels, a display format (`ip`, `url`, `code`), the synonym
   keys that fold into it and, for a key such as `port`, the classes whose
   assets may hold it. A type's schema is its attributes plus
   `common_properties` (platform keys and the CTIS technical blocks).
   The generator checks that every attribute and common key is declared,
   that no synonym is an attribute, and that a class-restricted key is
   declared only by types of those classes. `GET /api/v1/asset-types`
   serves the dictionary; the web gets it generated.
2. *Canonical keys, folded on write.* An asset's addresses are
   `ip_addresses` (a list, IPs in canonical form). Ingest, REST create and
   update, and CSV import fold every synonym into its key
   (`asset.NormalizeProperties`): string and list values merge, a
   comma-separated string splits, a value that is not an address is
   dropped. An object under a synonym name (the CTIS technical
   `ip_address` block) never folds; only its address joins the list.
3. *Never on the wrong type.* Before a report's assets are stored, a port
   (with the open-port keys that came with it) on a domain, subdomain,
   host or IP address becomes that asset's `host:port/proto` open-port
   service, linked by `exposes`; other misplaced keys are dropped. The
   routed service is an ordinary report asset: exclusions, attribution and
   the bound command's targets apply to it (RFC-040 §5.3), so routing lets
   a report write nothing it could not report directly. REST and import
   refuse a misplaced key (400).
4. *Addresses are relationships.* A domain `resolves_to` an IP asset per
   address (the property is the summary); the edge's `created_at` is first
   seen and `last_verified` last seen, refreshed by every sighting. An edge
   changes its domain, so a report that may not change the domain adds
   none.
5. *One reader.* `asset.IPAddresses` / `asset.PropertyStrings` read the
   canonical key and every synonym (rows not yet normalised); SQL reads
   build their predicate from `asset.AddressPropertyKeys`. The scattered
   key lists are gone.
6. *Existing rows.* A migration folds the synonyms of every stored asset
   and removes misplaced keys, keeping each changed row's previous
   properties for the down migration.
7. *Guards.* A source scan fails on any map index or map literal that uses
   a synonym key outside its allow-list; tests check that every key ingest
   writes itself is in the stored type's schema. A scanner key outside the
   schema is kept, and ingest logs one warning per report listing such
   keys; third-party and custom keys use the `x_` prefix.

**Threat model.** Properties are tenant data written by sensors, importers
and people. The schema adds no new input: synonyms fold within one asset,
routing adds at most one service per report asset under the same
exclusion, attribution and command-target rules, and every lookup stays
tenant-scoped (the relationship upsert's conflict key includes
`tenant_id`). Address matching for exclusions reads more keys, never fewer,
so it can only exclude more (fail closed).

#### 6.3.10 Property names (amendment, 2026-10-08)

**Problem.** The per-type web pages read and wrote about sixty property
keys the schema does not have (`os`, `cpu_cores`, `arch`, `open_ports`,
`cert_issuer`, `cert_not_after`, `expiry_date`, `encryption`,
`is_publicly_accessible`, `ssl`, `http_status` …), so a scanned host showed
an empty OS column, a certificate entered by hand filed its dates under
"Other", and three headline counts counted keys nothing writes. The schema
itself mixed boolean spellings (`mfa_enabled`, `encrypted`, `archived`,
`uses_ssl_pinning`) and timestamps without `_at` (`last_used`,
`last_login`).

**Design.** The naming rules are in the architecture page
([Property names](../architecture/asset-inventory-v2.md#property-names)).
What this amendment changes:

1. The generator enforces the mechanical rules (boolean `is_`/`has_`,
   timestamp `_at` or a spec term, plural lists) and one shape per key
   across types; synonyms are allowed on scalar keys too (they move,
   keeping their type).
2. 22 boolean keys, 3 timestamps and one duration were renamed, each old
   name kept as a synonym (they were the published schema):
   `has_tls`, `is_auth_required`, `has_rate_limiting`, `has_cors`,
   `has_ssl_pinning`, `has_edr`, `has_mfa`, `has_rbac`, `has_pod_security`,
   `has_network_policies`, `has_scan_on_push`, `is_encrypted` (from
   `encrypted` and `encryption_enabled`), `has_immutable_tags`,
   `is_archived`, `is_privileged`, `is_ssl_enforced`, `is_public` (from
   `publicly_accessible`), `has_versioning`, `has_logging`, `has_dhcp`,
   `has_flow_logs`, `last_used_at`, `last_login_at`, `last_modified_at`,
   `max_session_duration_seconds`. Scanner and stored spellings join as
   synonyms: `os` → `os_name`, `web_server` → `server`, `self_signed` →
   `is_self_signed`, `encryption` → `is_encrypted`.
3. Network devices gain `vendor`, `model`, `firmware_version`,
   `management_ip`, `serial_number`; HTTP services `chain_status_codes`.
4. Migration `001331` folds stored synonyms (and a certificate's
   `fingerprint` into `fingerprint_sha256`, once: the word is too generic
   to be a synonym). Its down is a documented no-op: a fold is not
   reversible.
5. The web names keys through the generated `AssetPropertyKey`; a guard
   test fails on hand-written `.metadata.<key>` reads in asset code.
   `GET /assets/stats?count_by=` accepts only schema keys (synonyms fold),
   at most 10.

**Threat model.** No new input or endpoint. The fold runs inside each
asset's own row. `count_by` was an unbounded list of arbitrary JSONB keys,
each one more GROUP BY over the caller's (data-scoped) assets; it is now
capped and limited to the schema, which only narrows what a member can ask
for.

### 6.4 The services table (evolve `asset_services`)

The table keeps its name, so the merge plan, RLS shadow policies and
`/api/v1/services` routes stay valid (F1, F8). Its role changes from
"manual sidecar" to "the row ingest maintains".

#### 6.4.1 Columns added

| Group | Column | Type | Notes |
|---|---|---|---|
| Identity | `transport` | enum tcp/udp/sctp | Replaces the overloaded `protocol`; `protocol` is kept as a compat view column for one release |
| | `scheme` | text | `http`, `https` or NULL for non-web |
| | `host` | text | Denormalised host name (the asset name) for search and sort without a join |
| | `ip` | inet | Address the service answered on |
| | `legacy_asset_id` | uuid NULL FK assets | The `service`-type asset this row replaces (§6.8). Joins the merge plan |
| Network | `asn` int, `asn_org` text, `cloud_provider` text, `cdn` text, `is_cdn` bool | | From cdncheck/asnmap or RIR data |
| HTTP | `http_status` smallint, `http_title` text(512), `http_title_hash` bytea(8), `http_server` text(256), `http_content_length` bigint, `http_content_type` text(128), `http_final_url` text(2048), `http_redirects` smallint, `favicon_mmh3` int, `jarm` text(62), `response_time_ms` int | | `http_title_hash` = first 8 bytes of SHA-256 of the normalised title; used for group-by and indexing |
| TLS | `tls_subject_cn` text, `tls_issuer_org` text, `tls_issuer_cn` text, `tls_sans` text[], `tls_not_before` timestamptz, `tls_not_after` timestamptz, `tls_serial` text, `tls_fingerprint_sha256` bytea, `tls_self_signed` bool | | Leaf certificate only. Chains stay in the observation `value` |
| Labels | `system_labels` text[], `tags` text[] | | `tags` = custom labels (D2); `system_labels` maintained by the label engine (§6.7) |
| Tech | `technology_ids` int[] | | Denormalised from `service_technologies` for GIN filtering |
| Screenshot | `screenshot_id` uuid NULL, `screenshot_phash` bigint | | Latest capture |
| Findings | `open_finding_count` int, `max_open_severity` smallint | | Maintained on finding status transitions (§6.4.4) |
| Time | `first_seen` (rename of `discovered_at`), `last_seen` (rename of `last_seen_at`), `last_changed_at` | | |
| Lifecycle | `state` (existing enum) + `archived_at`, `archived_reason` | | Archive is a state, never a delete |
| Lineage | `discovered_by_run_id`, `discovery_source` (existing) | | |

The unique key becomes `(tenant_id, asset_id, port, transport)`, from
`(asset_id, port, protocol)`. The `service_type` CHECK list stays and gets
`unknown`.

#### 6.4.2 DNS columns on the host asset

DNS belongs to the name, not to the port. These columns are added to
`assets` and filled for `domain` and `subdomain` assets:

| Column | Type |
|---|---|
| `dns_a` | `inet[]` |
| `dns_aaaa` | `inet[]` |
| `dns_cname` | `text[]` (chain, in order) |
| `dns_resolved_at` | `timestamptz` |
| `apex_domain` | `text` |

The full RRsets stay in the `dns` observation facet (§6.16). This
replaces the flattened `record_type` / `resolved_ip` / `cname_target`
properties from migration 000134 for new data. The old keys are
backfilled and then kept read-only.

#### 6.4.3 Indexes (100k–1M services per tenant)

All indexes are tenant-leading. Partial indexes use `WHERE state <> 'archived'`
(written `live` below), because default views hide archived rows.

| Purpose | Index |
|---|---|
| List default sort | `(tenant_id, last_seen DESC, id)` live |
| Port facet / group-by | `(tenant_id, port)` live |
| Status | `(tenant_id, http_status)` live |
| Web server | `(tenant_id, http_server)` live |
| Title group-by | `(tenant_id, http_title_hash)` live |
| Host | `(tenant_id, asset_id)` (exists as FK path); `gin (host gin_trgm_ops)` for `host:*foo*` |
| Title search | `gin (http_title gin_trgm_ops)` |
| IP | `(tenant_id, ip)` btree; `gist (ip inet_ops)` for CIDR containment |
| Labels | `gin (tags)`, `gin (system_labels)` |
| Technologies | `gin (technology_ids)` on services; `(tenant_id, technology_id, version)` on `service_technologies` |
| TLS expiry | `(tenant_id, tls_not_after)` live |
| ASN / CDN / cloud | `(tenant_id, asn)`, `(tenant_id, cloud_provider)` live |
| Findings | `(tenant_id, max_open_severity) WHERE open_finding_count > 0` |
| Assets apex / CNAME | `(tenant_id, apex_domain)`; `gin (dns_cname)`; `gin (name gin_trgm_ops)` |

Write cost: about 14 indexes on a table that changes on rescans. Two
things keep this cheap:

- Ingest updates a service row **only when a facet hash changed** (§6.16).
  Unchanged rescans update `last_seen` alone, and that column is in one
  index.
- The partial predicate keeps archived rows out of every index.

#### 6.4.4 Services and findings ("Issues found")

- Add `findings.service_id uuid NULL` (FK `asset_services`,
  `ON DELETE SET NULL`), plus the partial index
  `(tenant_id, service_id) WHERE status IN (open statuses)`.
- **Mapping at ingest:**
  1. If CTIS `Finding.Network.port > 0`, use (asset, port, transport).
  2. Else, for web findings, take the matched URL's host and port. The
     scheme gives the default port.
  3. Else NULL. A host-level finding is not a service finding.
- **Backfill:** existing findings on a `service`-type asset map through
  `legacy_asset_id`. The remaining open network findings are matched from
  the `port` parsed out of their fingerprint where the VA fingerprint
  holds one. Everything else stays NULL, reported in the migration log
  with a count.
- **Counters.** `open_finding_count` and `max_open_severity` on services
  are recomputed in the same transaction as the finding status change, in
  the path that already maintains `assets.finding_count`. A nightly
  reconciler corrects drift and logs every correction. List pages read
  the counters, so there is no N+1. The detail drawer runs one grouped
  query: `SELECT severity, count(*) ... WHERE service_id = $1 GROUP BY 1`.
- **"Affected services":** `count(*) FROM asset_services WHERE tenant_id=$1
  AND open_finding_count > 0 AND live`, which is index-only. The number is
  honest only for findings that carry a service. The endpoint returns
  `coverage = mapped_open_findings / open_network_findings` beside it, and
  reports `insufficient_data` when that is below 50 %.
- `service_id` is added to the merge plan's finding handling. Findings
  move with their asset, and their `service_id` is remapped to the
  surviving service by `(port, transport)`.

#### 6.4.5 Source records, correlation and identity (practices I1–I4)

Three layers, built mostly from parts that already exist:

| Layer | Asset | Service | Status |
|---|---|---|---|
| 1. Per-source record (raw, one per source or connector instance) | `asset_sources` (`contributed_data`, `first_seen_at`, `last_seen_at`, `confidence`, `is_primary`), exists since 000014 | **new** `service_sources(tenant_id, service_id, source_type, source_id, contributed jsonb, first_seen, last_seen, last_seen_run_id)` | add `last_seen_run_id` and `tenant_id` to `asset_sources` |
| 2. Correlation link (which records were joined, by which key, and who decided) | implicit today: `asset_sources.asset_id` + RFC-028 `asset_identifiers` | same, through the service's asset | **new** columns on `asset_sources`: `linked_by` (`strong_id`/`name`/`hostname_window`/`ip_window`/`manual_merge`), `linked_at`, `linked_run_id`. The view `asset_links` exposes them |
| 3. Canonical row with preferred fields | `assets` | `asset_services` | preferred fields recomputed from layer 1 with RFC-003 priority (`priority_gate.go`); last-writer-wins remains only where no priority is configured |

**Ingest stays fast.**

- Ingest upserts the source record and the canonical row.
- It does an **inline strong-key match only**: an RFC-028 strong
  identifier or an exact canonical name. Findings in the same report need
  an asset id at once, which is why the strong-key match cannot wait for
  the batch job.

**The correlation job runs after ingest.**

- Scope: single-flight per tenant and scan zone. It is leased, so two
  runs never overlap (research 02 finding 6).
- It runs after each completed scan run, debounced 5 minutes, and nightly.
- Steps:
  1. **Windowed matches.** It runs RFC-028's hostname and IP matches.
     These still only *propose* a merge to the dedup review queue; they
     never merge automatically.
  2. **Preferred fields.** It recomputes the preferred fields of every
     asset and service touched since the last run.
  3. **Snapshot.** It writes the change rows for rollups (§6.17).

**Key order.** The deterministic key order stays RFC-028's (strong id,
then exact name, then hostname in a window, then IP in a window). The IP
window is explicit and expires (default 3 days), so a
reused cloud or DHCP address does not join two machines.

**The zone boundary (I4).** Identity keys for **private** addresses
(RFC 1918, ULA, CGNAT) include the scan zone id. `10.0.0.5` seen from
zone A and from zone B are therefore two assets. Public addresses and DNS
names correlate tenant-wide. The tenant is always a hard boundary (D16).

**Manual merge and split, both audited.**

- Merge is today's `ApproveAndMerge`.
- Split is new: `POST /api/v1/assets/{asset_id}/split` with
  `{source_record_ids[]}`. It moves the chosen source records, with their
  findings and services, to a new asset. This uses the merge plan in
  reverse, for the tables keyed by source.
- `split` is not in RFC-041's closed verb list. It is proposed as an
  addition in this RFC's review (D17), and the fallback is
  `POST /api/v1/asset-splits` as a resource.

**Source scope in queries (I1).** `source:<source_type>[/<source_id>]` in
OQL restricts a query to records from that source, using
`contributed_data` for source-specific fields. The default scope is the
canonical layer. Facets can be asked for per source:
`facets?source=nessus`.

### 6.5 OQL: the inventory query language

#### 6.5.1 Grammar

```ebnf
query    = [ or_expr ] ;
or_expr  = and_expr { "OR" and_expr } ;
and_expr = unary { [ "AND" ] unary } ;            (* juxtaposition = AND *)
unary    = [ "NOT" | "-" ] primary ;
primary  = "(" or_expr ")" | group | clause | text ;
group    = "services" ":" "(" or_expr ")" ;           (* same-service grouping, asset queries *)
clause   = field op value_list | field ":*" ;          (* ":*" = field is non-empty *)
op       = ":" | "=" | "!=" | ">" | ">=" | "<" | "<=" ;
value_list = value { "," value } ;                 (* comma = any-of *)
value    = quoted | bare | number | duration | cidr | "null" ;
duration = [ "-" ] digits ( "m" | "h" | "d" | "w" ) ;   (* relative to now *)
text     = quoted | bare ;                         (* free text → search *)
```

- `:` means:
  - *equals* for enums and numbers;
  - *matches* for strings: case-insensitive and fuzzy, where `*` is a
    wildcard (`host:*.staging.acme.com`, `title:*admin*`);
  - *contains* for CIDRs (`ip:10.0.0.0/8`).
- `=` is **exact, case-sensitive** for strings: `title="Sign In"`. This
  is the split between fuzzy `:` and exact `=` (I8).
- `field:*` means the field is present and non-empty, for example
  `screenshot:*` or `tls.issuer:*`.
- **Same-service grouping (I8).** On an asset query, `port:22 scheme:ssh`
  could be satisfied by two different services of the host.
  `services:(port:22 AND banner:*OpenSSH_7*)` requires one service to
  match every condition inside the parentheses. It compiles to a single
  `EXISTS (SELECT 1 FROM asset_services s WHERE s.asset_id = a.id AND
  <all inner clauses on s>)`. Service fields used **outside** a group
  each get their own `EXISTS`. `Explain()` says which one applies.
- A regex operator (`=~`) is deliberately not offered (T8).
- Keywords are case-insensitive. Values are case-insensitive for host,
  label and technology names.
- Examples:
  - `port:443,8443 tech:nginx tls.expires<30d`
  - `label:"Login Portal" -label:staging status:200,401`
  - `(tech:jenkins OR title:*jenkins*) is.public:true`
  - `first_seen>-7d asn:13335`

#### 6.5.2 Field registry

Each field declares:

- its subject (asset, service or both);
- a type: string, int, inet, time, enum, bool, label, technology;
- the allowed operators;
- a fixed SQL fragment, or a join the compiler adds;
- whether it is facetable and groupable;
- which index serves it.

**A field not in the registry is a 422 error naming the unknown field.**

| Field | Subject | Type / ops | Facet | Group | Notes |
|---|---|---|---|---|---|
| `host` | S | string `: = !=` wildcard | | ✓ | `asset_services.host` |
| `domain` | A,S | string | ✓ | ✓ | `assets.apex_domain` |
| `ip` | S | inet `: =` CIDR | ✓ | ✓ | `ip <<= $n` for CIDR |
| `port` | S | int, ranges | ✓ | ✓ | |
| `transport`, `scheme` | S | enum | ✓ | | |
| `status` | S | int | ✓ | ✓ | `http_status` |
| `title` | S | string wildcard | ✓ (top) | ✓ | groups by `http_title_hash` |
| `server` | S | string | ✓ | ✓ | `http_server` |
| `content_length` | S | int ranges | | | |
| `favicon` | S | int | ✓ | ✓ | mmh3 |
| `tech` | S | technology | ✓ | ✓ | name; `tech.version` with semver-ish compare (§6.7.3); `tech.category` |
| `label` | A,S | label | ✓ | ✓ | system ∪ custom; `label.source:system\|custom` |
| `cname` | A,S | string wildcard | ✓ | ✓ | `assets.dns_cname` |
| `asn`, `asn.org`, `cloud`, `cdn` | S | int / string | ✓ | ✓ | |
| `tls.issuer`, `tls.cn`, `tls.san` | S | string | ✓ | ✓ | |
| `tls.expires` | S | time/duration | | | `tls_not_after` |
| `type`, `sub_type` | A | enum | ✓ | | asset type |
| `criticality`, `effective_criticality` | A | enum | ✓ | | effective uses the read-time MAX (§3.5) through the existing lookup |
| `owner`, `bu`, `business_service` | A | id / `me` / `null` | ✓ | | |
| `attribution` | A | enum confirmed/needs_review/… | ✓ | | RFC-036 / #835; `null` = legacy confirmed |
| `exposure`, `is.public`, `is.crown_jewel` | A | enum / bool | ✓ | | |
| `state` | A,S | enum active/stale/archived | ✓ | | default `state!=archived` unless present |
| `findings.open`, `findings.max_severity` | S | int / enum | ✓ | | counters (§6.4.4) |
| `first_seen`, `last_seen`, `changed` | A,S | time | | | `changed` = `last_changed_at` |
| `group` | A,S | asset group id | ✓ | | static membership or dynamic expansion (bounded, §6.12) |
| `screenshot.cluster` | S | id | ✓ | ✓ | §6.14.4 |

The **subject** of a query is chosen by the endpoint: `/services` or
`/assets`. Asset fields used on a service query join through `asset_id`.
Service fields used on an asset query compile to `EXISTS (SELECT 1 FROM
asset_services s WHERE s.asset_id = a.id AND …)`.

#### 6.5.3 Compiler

1. **Parse** to an AST, with limits (T8). A syntax error returns 400 with
   the position (`code: OQL_SYNTAX`).
2. **Resolve and type-check** against the registry: unknown field,
   operator not allowed, bad CIDR or bad duration → 422 (`OQL_INVALID`).
3. **Normalise:**
   - lower-case values where the field is case-insensitive;
   - expand `me`;
   - convert durations to absolute times at evaluation time; a stored
     query keeps them relative;
   - sort commutative children so equivalent queries hash equally;
   - the canonical form is stored next to the source text.
4. **Emit SQL.** The output is a `WHERE` fragment plus its arguments, with
   joins de-duplicated. The compiler always prepends `tenant_id = $1`
   and, for non-admin callers, the data-scope predicate (the existing
   `user_accessible_assets` clause, via `asset_id` for services).
5. **Version.** Stored queries keep `oql_version`. A grammar change ships
   a migration function for stored queries, or both versions are kept
   until every stored query is rewritten.

The same package exports `Explain(query)`, which returns sentences such as
"services on port 443 or 8443 whose technology is nginx and whose
certificate expires within 30 days". The UI shows it under the filter bar,
and policy previews show it too.

**URL form.** `?q=<oql>` on list, facet, group, export and preview
endpoints. The existing typed parameters on `GET /assets` remain. They
are translated into OQL clauses internally and AND-ed with `q`, so old
clients keep working.

### 6.6 Facets, group-by and lists

#### 6.6.1 Facets

`GET /api/v1/services/facets?q=<oql>&fields=port,tech,label&size=10`
(and `/api/v1/assets/facets` with the same contract, replacing the JSONB
version; the old `GET /assets/facets` response shape is kept under
`?legacy=1` for one release).

```json
{
  "as_of": "2026-10-03T09:12:00Z",
  "source": "live",
  "total": { "value": 18234, "exact": true },
  "facets": {
    "port": { "values": [ { "value": 443, "count": 9120 }, { "value": 80, "count": 7001 } ],
              "other": 2113, "exact": true },
    "tech": { "values": [ { "value": "nginx", "id": 412, "count": 5120, "icon": "/api/v1/technologies/412/icon" } ],
              "other": 0, "exact": false, "reason": "timeout_lower_bound" }
  }
}
```

**Semantics.** For a query that is a conjunction of facet selections,
which is what the facet menu builds, each field's counts are computed
with **that field's own clause removed**. This is the standard
multi-select facet: selecting `port:443` still shows the counts for 80.
For any other query shape, counts use the full query. The response says
which mode it used (`"mode": "multiselect" | "full"`).

**Execution:**

1. **Unfiltered request** (empty `q`, admin or unrestricted data scope):
   read `inventory_facet_counts`, a per-tenant table of
   `(tenant_id, subject, field, value, count, computed_at)`. A debounced
   job recomputes a tenant's rows at most once per 60 s after any
   ingest, label or archive change; the trigger is the same dirty-flag
   outbox as policies (§6.15.4). The response has `"source": "snapshot"`
   and `as_of`.
2. **Filtered or data-scoped request:** one `GROUP BY` per field. Fields
   run concurrently on separate pooled connections, at most 4 per
   request. Each has `statement_timeout = 1500ms` and
   `LIMIT size + 1`.
   - If a field times out, it is re-run as a bounded sample:
     `WITH s AS (SELECT … LIMIT 10000)`. The counts from the sample are
     returned with `"exact": false, "reason": "timeout_lower_bound"`, and
     the UI shows them as "≥".
   - No number is ever extrapolated.
3. Array fields (tech, label, cname) count each element:
   - tech: `unnest(technology_ids)`, or a join to `service_technologies`
     when `tech.version` is requested;
   - label: `system_labels || tags`;
   - cname: `dns_cname`.

#### 6.6.2 Group-by

The owner's design screenshots group services by technology, port, label,
domain, host, IP, CNAME, status code, title or web server. Each group
needs its value, a count, its own pagination, export and "scan this
group".

```
GET /api/v1/services/groups?group_by=tech&q=<oql>&page=1&per_page=20&items_per_group=5&sort=-count
```

```json
{
  "group_by": "tech",
  "data": [
    { "value": "jQuery", "key": "tech:412", "count": 3120, "exact": true,
      "items": [ /* first items_per_group services, default list sort */ ],
      "query": "tech:\"jQuery\" AND (<q>)" }
  ],
  "total": 214, "page": 1, "per_page": 20, "total_pages": 11
}
```

- **Groups page by count.** The group query is the facet query for that
  field, without the top-N cut-off, ordered and paged. The **first page
  of items** for the visible groups comes from one window query:

  ```sql
  SELECT * FROM (
    SELECT s.*, row_number() OVER (PARTITION BY <group expr> ORDER BY s.last_seen DESC, s.id) rn
    FROM asset_services s WHERE <compiled q> AND <group expr> = ANY($groups)
  ) x WHERE rn <= $items_per_group
  ```

  That is two queries per page, whatever the number of groups.
- **Per-group pagination** uses the plain list endpoint with the group's
  `query` string: `GET /api/v1/services?q=<group query>&page=2`. There is
  no second list implementation. The group's `key` is stable, so the UI
  can deep-link a group.
- **Per-group export and scan** use the same `query`:
  `POST /api/v1/services/exports {q}` and
  `POST /api/v1/scans/preview {selection: {q}}`.
- **Group expressions and their indexes** (from §6.4.3):

  | group_by | expression | index |
  |---|---|---|
  | `tech` | `unnest(technology_ids)`, or join `service_technologies` | `gin (technology_ids)` / `(tenant_id, technology_id, version)` |
  | `port` | `port` | `(tenant_id, port)` |
  | `label` | `unnest(system_labels \|\| tags)` | GIN on both |
  | `domain` | `a.apex_domain` | `(tenant_id, apex_domain)` |
  | `host` | `asset_id` (shown as `host`) | `(tenant_id, asset_id)` |
  | `ip` | `ip` | `(tenant_id, ip)` |
  | `cname` | `unnest(a.dns_cname)` | `gin (dns_cname)` |
  | `status` | `http_status` | `(tenant_id, http_status)` |
  | `title` | `http_title_hash` (shows a sample title) | `(tenant_id, http_title_hash)` |
  | `server` | `http_server` | `(tenant_id, http_server)` |

#### 6.6.3 Lists

- `GET /api/v1/services?q=&sort=-last_seen&page=&per_page=`, and the same
  on `/assets`. Pagination follows RFC-041: `page`/`per_page`, with a
  maximum of 100.
- **Totals:** when the count would exceed 10,000 on a filtered query,
  `total` is computed with `LIMIT 10001` and returned as
  `{ "total": 10000, "total_exact": false }`. The UI shows "10,000+".
- **Exports and very large reads** use `cursor` and `next_cursor` over
  `(sort key, id)` keyset pagination (RFC-041 §5).
- **Exports** are jobs: `POST /api/v1/services/exports` → 202 +
  `Location`. Formats are CSV and NDJSON. The file goes to `FileStorage`
  with a 24-hour expiry, under the T5 formula guard and the
  `assets:export` permission.

#### 6.6.4 Saved filters

Table `saved_filters`:

| Column | Notes |
|---|---|
| `id`, `tenant_id` | |
| `owner_user_id` | |
| `name` | |
| `subject` | asset or service |
| `query`, `query_canonical`, `oql_version` | |
| `visibility` | `private` / `tenant` / `roles` with `role_ids` |
| `pinned` | |
| `created_at`, `updated_at` | |

- Read access is the visibility rule **and** the reader's own data scope:
  a shared filter never widens what the reader can see.
- "Save filter" in the UI creates a saved filter. "Save as group" creates
  a dynamic group (§6.12) with a copy of the query. The group does not
  follow later edits to the saved filter; the two have different
  lifecycles and audit trails.

### 6.7 Labels

#### 6.7.1 Model

```
labels(id, tenant_id NULL for system, key, display_name, kind system|custom,
       color, description, rule_set_version NULL, created_by, created_at)
label_assignments(tenant_id, label_id, subject_type asset|service, subject_id,
       source manual|rule|policy, rule_id, rule_version, confidence 0-100,
       evidence jsonb, assigned_by, origin, assigned_at,
       PRIMARY KEY (tenant_id, label_id, subject_type, subject_id))
```

- **System labels:** tenant-NULL rows seeded from the rule set. A tenant
  can hide a system label, but cannot edit it.
- **Custom labels:** the existing `assets.tags` and the new
  `asset_services.tags` arrays. They stay the storage for custom labels
  (D2), because scope rules and assignment rules key on `assets.tags`
  (§3.5). `label_assignments` records provenance for custom labels only
  when they are set by a policy or a bulk action. Manual edits keep using
  the array, and the audit log records them.
- **System label storage:** `label_assignments` is the record of truth.
  `system_labels text[]` on services and assets is a denormalised copy for
  filtering, written in the same transaction.
- **Migration:** stop CTIS from copying technologies into tags (F3; ctis
  change + ingest guard). Existing tags that exactly equal a technology
  name detected on the same asset are moved out of `tags` into technology
  detections; the migration log lists them. Tags that do not match stay,
  because a human may have chosen them.

#### 6.7.2 The system rule set

The rule set is versioned YAML in the repository
(`api/internal/app/labels/rules/v1/*.yaml`) and embedded in the binary.
Each rule:

```yaml
id: login-portal
label: Login Portal
version: 3
subject: service
when: >                      # OQL
  (title:*login*,*sign in*,*signin* OR http.form.password:true)
  status:200,401
confidence: 70
evidence: [http_title, http_status]
```

- The starting set covers:
  - Login Portal, Staging Environment, API Endpoint;
  - Jenkins CI, GitLab, Grafana, Kibana and other admin consoles;
  - Default Page, Directory Listing, Cloud Storage Bucket, VPN Gateway;
  - Parked Domain, Expired Certificate, Self-signed TLS, Behind CDN;
  - Dev/Test hostnames.
- Each rule is an OQL condition over registry fields, plus a few
  label-only fields fed by the HTTP observation: `http.form.password`,
  `http.header.<allowlisted name>`, and body keyword hits computed **on
  the sensor** with a fixed keyword list. Bodies are never shipped.
- **Evaluation:**
  - on service insert or change (from the observation diff, §6.16);
  - on a rule-set version bump, as a backfill job per tenant, batched
    and resumable.
- A rule that no longer matches **removes** its own assignment. It never
  touches assignments from other sources.
- **Confidence** is the rule's static value. When a rule's evidence comes
  from a screenshot cluster (§6.14.4) and a human labelled one member,
  the propagated labels get `confidence = 60` and `source = rule`, with
  the cluster id as evidence. People can confirm them in bulk.
- **Tenant custom rules** (the same YAML, written in the UI) are a
  policy with `add_label`. They are not a second rule engine (§6.15).

#### 6.7.3 Technology catalog

The owner's design screenshots show technologies with categories (font
scripts, tag managers, analytics, web servers, JS frameworks and
libraries, …), a short description, an icon and a version ("jQuery
3.3.1").

**Source.** httpx detects technologies with
`projectdiscovery/wappalyzergo` (MIT code). Its fingerprint data comes
from `enthec/webappanalyzer` (**GPL-3.0**). OpenCTEM is GPL-3.0, so
importing that data (names, categories, descriptions, websites, CPE) is
licence-compatible, provided it is attributed in `NOTICE`. Icons are
third-party logos. They are imported from the same pinned release and
served from our own path (never hot-linked). A tenant can turn icons off,
and a missing icon falls back to a monogram.

**Tables:**

- `technology_categories(id, name, priority)`
- `technologies(id serial, slug unique, name, description, website, cpe,
  icon_sha256, category_ids int[], source 'webappanalyzer@<tag>',
  updated_at)`. This is global, not per tenant; a technology is public
  knowledge.
- `service_technologies(tenant_id, service_id, technology_id, version
  text NULL, version_key int[] NULL, confidence smallint, source,
  first_seen, last_seen, PRIMARY KEY (tenant_id, service_id,
  technology_id))`.
  - `version_key` is the version parsed into a sortable integer array
    (`3.3.1` → `{3,3,1}`). This makes `tech.version<3.5` an array
    comparison.
  - Unparseable versions stay text-only and match only `=`.

**Import.** An admin CLI command (`openctem-admin catalog import
webappanalyzer --tag vX`) and a release-time refresh. It is versioned;
the catalog's `source` tag is shown in the UI and the API. Unknown names
reported by a sensor are inserted as `source = 'sensor'` with no
description, and are never dropped.

**Wire.** httpx's JSON `tech` array is `Name:version`. The sensor keeps
it as given. The API splits it into name and version and resolves the
name to `technologies.slug`, case-insensitive.

**What this enables later:**

- "tech changed" alerts (§6.16);
- outdated-version checks, by joining `version_key` to the CPE in a
  future phase (out of scope here).

### 6.8 How the existing typed assets map in

| Today | v2 | Migration |
|---|---|---|
| `domain`, `subdomain`, `ip_address`, `host` assets | Unchanged; gain DNS columns, `apex_domain`, `system_labels` | Backfill DNS columns from `properties` (000134 keys); `apex_domain` via the public suffix list |
| `service` assets with sub-type `http` / `open_port` | One `asset_services` row each, `legacy_asset_id` → the old asset; host = parent host asset (found by `properties.host`/URL host through RFC-028 identity, created if missing) | Batched backfill job (10k rows per batch, resumable, idempotent on the unique key). The old asset stays, gets `system_labels = {legacy-service}` and is hidden from default views by an OQL default (`sub_type!=http,open_port` on the asset list) |
| `properties.ports` on hosts | `asset_services` rows (`discovery_source = 'legacy_properties'`) | Same job; `properties.ports` kept read-only for one release |
| `discovered_url` assets | Stay assets (endpoints are out of scope; a later RFC may add `service_endpoints`) | none |
| HTTP keys in `properties` (`status_code`, `title`, `web_server`, `technologies`, `cdn`, `ip`, `tls_version`) | Typed service columns + `service_technologies` | Same job |
| `assets.tags` | Custom labels (unchanged storage) | Technology-equal tags moved out (§6.7.1) |
| Findings on `service` assets | `service_id` set via `legacy_asset_id` | §6.4.4 backfill |
| Scans with `asset_group_ids` | Unchanged; static groups behave as today plus the gate | none |

**Ingest after the cutover.**

- CTIS `http_service` and `open_port` assets, and `Asset.Services`, which
  is dropped today (F2), upsert `asset_services` rows. They no longer
  create `service`-type assets.
- `UpsertBatch` gets its first caller.
- A tenant setting `inventory.legacy_service_assets` (default **off**
  after P0) keeps the old behaviour for one release, as an escape hatch.
- The merge plan gains `legacy_asset_id`, `service_technologies` (via
  service), `label_assignments` (subject asset), the observations subject
  columns and `findings.service_id` remapping. The coverage test enforces
  all of these.

**What does not break:**

- finding ids and their `asset_id`;
- scan definitions;
- RFC-028 identifiers;
- the merge plan's existing behaviour;
- the `/api/v1/services` routes, which keep their shape and gain fields;
- `/api/v1/assets` query parameters.

### 6.9 Discovery inputs, seeds and lineage

**Inputs** (seeds are RFC-036's `easm_seeds`; this RFC only consumes
them):

| Input | Kind | Where it runs | Output |
|---|---|---|---|
| Root domain | seed `root_domain` | API collectors (CT, RDAP, passive DNS keys) then sensor | subdomains → candidates or assets (RFC-036 gate) |
| CIDR / IP | seed `cidr` or scope target | sensor | IPs, services |
| ASN | seed `asn` | API (RIPEstat/Cymru) → CIDRs; sensor for probing | netblocks, IPs |
| Org / brand | seed `org_name` | API (RDAP org, cert subject O, `asnmap -org` with tenant key) | candidates only, never auto-confirmed |
| Cloud account | connector (RFC-036 P5) | API | assets, authoritative evidence (w = 1.0) |
| Manual / API | `POST /assets`, `POST /services`, import | API | assets, services (tenant-scanned evidence, O8) |

**Layered orchestration on sensors.** This is RFC-036 §6.6's "External
discovery (T1)" preset, unchanged. This RFC adds three things:

1. **httpx flags.** httpx keeps `-favicon -jarm -asn -cdn -tls-grab
   -tech-detect -title -status-code -web-server -content-length
   -content-type -location -ip -cname`. The sdk-go parser keeps every
   field (fixes F4).
2. **CTIS gains an `http` technical block** with typed fields matching
   §6.4.1, plus `tls` leaf fields on the service. This is a ctis minor
   release; the ctis-parity CI job enforces the mirror in api.
3. **An optional `screenshot` step** after httpx (§6.14), only for
   services with `scheme` set and only when the target gate passes.

`tlsx`, `cdncheck` and `asnmap` are optional. The sensor advertises them
through the RFC-033 manifest only when it ships them. When they are
absent, the same columns are filled from httpx's `-tls-grab`/`-cdn`/`-asn`
output, which covers the needed fields.

**Connectors (I6).** Cloud connectors (RFC-036 P5) and imports implement
one Go interface in `internal/app/connector`:

- `Fetch(ctx, instance) (raw, error)`: pure I/O, no retries, and it fails
  loudly;
- `Map(raw) ([]ctis.Asset, error)`: schema mapping;
- `Load(ctx, run, assets)`: idempotent upsert through ingest, stamped
  with the run;
- `ScopedCleanup(ctx, run)`: marks stale only the records of **this
  tenant, connector instance and account** that this run did not see.

The framework owns retries, rate limits, scheduling, credentials
(per-tenant `ListByProvider`, RFC-006) and the rule that `ScopedCleanup`
is skipped when any earlier step failed.

**Lineage.** RFC-036 puts `discovery_path` on candidates. Graph-cut
exclusions (§6.13) also need lineage for assets that are **already in the
inventory**, so this RFC adds one edge table for both:

```
discovery_edges(tenant_id, child_kind asset|candidate|service, child_id,
                parent_kind seed|asset|candidate, parent_id,
                edge_type ct_san|dns_resolve|cname|ptr|asn_prefix|rdap_org|
                          http_redirect|tls_san|port_scan|connector|manual,
                evidence_id NULL (easm_evidence), run_id, first_seen, last_seen,
                PRIMARY KEY (tenant_id, child_kind, child_id, parent_kind, parent_id, edge_type))
```

- **Writers:** ingest writes edges from CTIS provenance. The pipeline
  service knows which step's output fed which next step, and stamps
  `parent` on the CTIS asset. RFC-036 collectors write edges for
  candidates.
- **Read path:** "how was this found?" on the asset drawer is a recursive
  CTE capped at depth 8, and the reachability check in §6.13 uses the
  same query.

### 6.10 Associated domains (evidence-backed candidates)

These are RFC-036 P2 candidates. This RFC fixes what the inventory shows
and asks for. It does **not** add a second queue.

- **Kinds of association.** Each maps to a rule in RFC-036's table, with
  its weight:
  - shared certificate (SAN co-occurrence, 0.50);
  - same certificate subject O as an org seed (0.60);
  - same RDAP registrant org (0.60; GDPR redaction is never negative
    evidence);
  - shared non-provider nameservers (0.30);
  - same registrar alone: **0.0** (not a signal; shown only as context);
  - **acquisition / subsidiary**: a new rule `subsidiary_of` (0.40,
    medium; never auto-confirm). It is fed only by a tenant-entered
    subsidiaries list (name, acquisition date, source URL) or an
    integration with a tenant key. **We do not scrape** company
    databases.
- **Evidence fields shown per candidate**, all from `easm_evidence.observed`:
  - certificate CN, subject O, issuer, serial, not-before/not-after;
  - registrant org, registrar;
  - acquisition date and source URL.
- **Per-candidate enrichment** (cheap, T0):
  - reachability: resolves yes/no, with the A/AAAA count;
  - subdomain count from CT;
  - "first seen" from the CT `not_before`.
  These are shown with their `as_of`.
- **Review.** Accept / reject / dependency / monitor-only, with bulk and
  "apply to all with this evidence". These are RFC-036's actions. A
  rejection writes a tombstone and a graph cut (§6.13).
- **No cap** on results. The queue is paged and sorted by confidence ×
  potential impact.

### 6.11 The target gate

One function, `scope.Gate`, decides whether a target may be **actively
touched**. Every dispatch path calls it.

```
allowed(t) =
      t.subject not archived
  AND attribution(t.asset) allows active (RFC-036, #835; NULL = legacy confirmed)
  AND NOT excluded(name, aliases, resolved addresses, lineage ancestors)    (§6.13)
  AND tier(t) <= tier ceiling (RFC-036 §6.3)
  AND tool accepts t's type
```

**Output.** Every call returns `{allowed[], skipped[{target, reason}]}`,
where `reason` is one of:

- `archived`
- `stale` (allowed by default, configurable)
- `unconfirmed`
- `excluded:<exclusion_id>`
- `excluded_ancestor:<asset_id>`
- `tier_ceiling`
- `type_incompatible`
- `over_cap`
- `over_budget`

**Call sites.** These are the existing path plus every bypass from F16:

| Path | Today | With this RFC |
|---|---|---|
| Scan trigger (`resolveScanTargets`) | exclusions by name + #835 attribution | full gate |
| RFC-030 claim | none | **re-check** at claim time (cheap: name/IP/attribution already loaded; exclusions cached per tenant with a version counter) |
| Pipeline step hop (RFC-036 §6.6) | none (`run.go:1100`) | full gate on each hop's planned targets |
| `POST /pipelines/runs` with `context.targets` | bypass | full gate |
| Scan-coverage dispatcher | bypass (`scheduler.go:242`) | full gate |
| Quick / ad-hoc scans | exclusions | full gate |
| Policy `trigger_scan` | n/a | full gate + budget |
| Validation re-check (RFC-011.2) | none | full gate |

**Preview first.**

`POST /api/v1/scans/preview` takes a body of
`{selection: {q | asset_group_id | service_ids | asset_ids}, scan_profile_id | tools[]}`
and returns:

```json
{ "total": 1840, "in_scope": 1602,
  "skipped": { "excluded": 120, "unconfirmed": 96, "archived": 12, "type_incompatible": 10 },
  "samples": { "excluded": [ { "target": "vpn.acme.com", "reason": "excluded:7f…" } ] },
  "budget": { "remaining_today": 5000, "after": 3398 },
  "preview_token": "…" }
```

`POST /api/v1/scans` with `selection` and the `preview_token` creates the
scan. The token binds the canonical selection and its counts for 15
minutes. If the gate result differs by more than 5 % at create time, the
API answers 409 `PREVIEW_STALE`.

**The gate runs again at dispatch.** The preview informs the decision;
it does not authorise anything.

**Budgets.** A per-tenant daily budget of (targets × tier) is enforced
here; RFC-036 §6.7 introduces it. Each policy also has its own budget
(§6.15).

### 6.12 Groups: static and dynamic, both scannable

`asset_groups` gains these columns. `group_type` comes back with a real
implementation, which honestly reverses 000205.

| Column | Notes |
|---|---|
| `kind` | `static` (default, today's rows) or `dynamic` |
| `subject` | `asset` or `service` |
| `query`, `query_canonical`, `oql_version` | dynamic groups only |
| `origin` | `manual`, `auto_discovery`, `connector`, `policy`, `seed` |
| `seed_id` | NULL unless the group came from a seed |
| `cadence` | `none`, `daily`, `weekly`, `monthly` or a cron expression, within the RFC-036 O9 floors |
| `scan_profile_id` | NULL unless set |
| `last_run_id`, `last_run_at`, `last_run_duration_ms` | |
| `member_count`, `service_count`, `counts_as_of` | |
| `verified_root` | bool, derived: any seed of the group is a verified root domain |

- **Static groups** keep `asset_group_members`. They may now also contain
  services, through `asset_group_service_members(asset_group_id,
  service_id)`, which joins the merge plan.
- **Dynamic groups** have no stored membership. Membership is the query,
  evaluated:
  - **at dispatch**, which is authoritative: `resolveScanTargets` expands
    the query with keyset paging up to the 10,000 cap. Each target then
    goes through the gate. A dynamic group never freezes a stale member
    list into a scan;
  - for display: `member_count` and `service_count` are refreshed by the
    facet-snapshot job, and `counts_as_of` is shown beside them.
- **"Asset groups as discovery runs".** A group with
  `origin = auto_discovery` or `seed` shows `last_run_at`, the duration,
  the service count and `verified_root`. These are real values from
  `scan_runs`. When nothing has run, the list shows "never run", not 0.
- **Per-group cadence** creates or updates a scan that targets the group,
  through the existing scan scheduler (`api/internal/app/scan/scheduler.go`).
  This avoids a second scheduler; the inert scope-schedules feature
  (Scoping IA D10) has since been removed (migration 001069 drops
  `scan_schedules`).
- **Sharing.**
  - Who can see a group is decided by RBAC (`assets:groups:read`) and the
    viewer's data scope.
  - A dynamic group's members are always filtered by the viewer's data
    scope. The query is shared, not the result.
  - There are no public or anonymous links. A link to a group is a normal
    authenticated URL.
- **The `group:` OQL field.** For a static group it is a semi-join. For a
  dynamic group it is the group's query, inlined. Nesting is limited to 2
  levels, and cycles are rejected at save time.

### 6.13 Exclusions: one model, three enforcement points

**Model.** The existing `scope_exclusions` table and its approval
workflow (F18) are extended:

| Column | Values |
|---|---|
| `applies_to` | `global` (default), `scope_target`, `asset_group` |
| `applies_to_id` | the target or group id, when not global |
| `pattern_kind` | `exact`, `wildcard`, `cidr`, `range` |
| `effect` | `discovery_and_dispatch` (default), `dispatch_only` |

- **Wildcard semantics are made explicit (F17):**
  - `*.x` matches subdomains only (**superseded by RFC-054 §4.1**: `*.x`
    now matches `x` and every name below it);
  - `x` matches the name only;
  - `**.x` is accepted and stored as `*.x`;
  - mid-label wildcards such as `test.*.x` match exactly one label.
- **Existing rows keep their old behaviour.** A one-time migration
  rewrites each `*.x` exclusion into the pair (`x`, `*.x`), because
  `*.x` used to match the bare `x`, and records this in the audit log.
- **Matching is case-insensitive and IDNA-normalised.**
- **No regex**, because of ReDoS (T8).
- **The non-target types are split out.** `finding_type` and `scanner`
  exclusions move to `exclusion_kind = finding|scanner` and stop being
  matched against hosts.
- **Include patterns (`+`)** are not added to exclusions. Scope targets
  already are the allowlist; the gate uses them through RFC-036's
  `in_scope_target OR derived_from_seed`.

**Enforcement points:**

1. **Discovery.**
   - Collectors (CT, RDAP, …) do not create a candidate or pivot from a
     name that matches. CT ignoring exclusions (F16) is fixed in P1.
   - Ingest does not **create** an asset from a discovery source when the
     name or address matches an approved exclusion. The skip is counted
     on the ingest report as `skipped_excluded`. Assets the tenant
     created or targeted by hand are created anyway, but with
     `state = archived` and `archived_reason = excluded:<id>`, so the
     decision is visible.
2. **Dispatch.** The gate (§6.11).
3. **Graph cut.** When an exclusion is approved, a job walks
   `discovery_edges` from every matching node. Each descendant whose
   **every** path to a seed or manual root passes through an excluded
   node is archived with `archived_reason = excluded_ancestor:<asset_id>`.
   Descendants with another path stay.

**Already-inventoried matches** are archived, with the reason, by the same
job. They are never deleted.

- **When the exclusion is removed, rejected or expired**, the job
  un-archives exactly the rows whose `archived_reason` names it, unless a
  human archived them later; the state history decides.
- **Each change writes `asset_state_history`** with
  `change_type = status_changed` and `source = exclusion`.

**Preview.** `POST /api/v1/scope/exclusions/preview` takes `{pattern,
applies_to}` and returns the counts it would archive directly and through
the graph cut, plus samples, before the request is submitted for
approval. The approver sees the same preview.

### 6.14 Screenshots

#### 6.14.1 Capture (sensor)

- **Engine.** The sensor gets a small capture binary, `octm-shot`,
  written in Go on chromedp (MIT) and driving the Chromium that ships in
  the `full`/`platform` images. Option (b) in D7 is gowitness (GPL-3.0,
  run as a separate executable). An in-house binary is recommended,
  because every T3/T4 control must be enforceable in code, and gowitness
  does not expose request interception per scope.
- **Inputs.** The service URL and the observed IP. The address is pinned
  with `--host-resolver-rules="MAP <host> <ip>"`.
- **Controls (T3/T4):**
  - Chromium sandbox on, non-root, its own cgroup: 512 MB memory and
    1 CPU;
  - `--disable-background-networking`, `--disable-sync`,
    `--disable-extensions`, `--no-first-run`;
  - downloads denied (`Browser.setDownloadBehavior deny`), and service
    workers, WebRTC, notifications, geolocation, clipboard and camera
    disabled;
  - a fresh temporary profile per capture, deleted after use;
  - request interception that blocks:
    - private, loopback, link-local and metadata addresses, unless the
      zone is internal and the address is in scope;
    - non-HTTP(S) schemes;
    - responses over 5 MB;
  - viewport 1366×768, device scale 1;
  - timeouts: navigation 15 s, total 20 s, 10 redirects at most;
  - JavaScript on (pages are useless without it) but with a 5 s
    post-load budget, then capture;
  - egress through the zone's RFC-034 profile.
- **Output.** A PNG (full viewport, not the full page), the final URL, the
  title at capture and the HTTP status. The sensor also computes a 64-bit
  pHash and a dHash, as hints only.
- **Delivery.** `POST /api/v2/sensor/screenshots` (multipart, ≤ 2 MB,
  bound to the job lease and run id), a protocol v2 feature advertised in
  `hello`. The sensor never stores screenshots beyond the upload.

#### 6.14.2 Storage (API)

- **Decode and re-encode.** The API decodes the PNG with Go's
  `image/png`, which bounds dimensions to 1366×768 and refuses anything
  else. It re-encodes to **WebP** (quality 75) and a 320-px WebP
  thumbnail, and **recomputes the pHash itself**. It never trusts the
  sensor's hash, so a lying sensor cannot poison clusters.
- **What is stored.** Only the re-encoded files, never SVG and never the
  original bytes. Size caps: 400 KB full, 40 KB thumbnail. An image over
  the cap is re-encoded at a lower quality, and refused if it is still
  too large.
- **Where.** In `FileStorage` (local, S3 or MinIO), under the
  content-addressed key `screenshots/<tenant_id>/<sha256>.webp`. The
  tenant id is in the key and in the row, and identical pages dedupe
  within a tenant only.
- **Table `service_screenshots`:**

  | Column | Notes |
  |---|---|
  | `id`, `tenant_id`, `service_id`, `run_id` | |
  | `captured_at` | |
  | `sha256`, `thumb_sha256` | |
  | `phash`, `dhash` | bigint |
  | `width`, `height`, `bytes` | |
  | `final_url`, `title_at_capture` | capped and sanitised |
  | `http_status` | |
  | `cluster_id` | |
  | `expires_at` | |

  A new row is written **only when the pHash Hamming distance to the
  previous capture is greater than 4** (change-only, like observations).
  Otherwise `captured_at` of the latest row is refreshed.

#### 6.14.3 Serving

`GET /api/v1/services/{service_id}/screenshots` (list) and
`GET /api/v1/services/{service_id}/screenshots/{screenshot_id}/image?size=thumb|full`.

- Access requires `assets:read`, data scope and tenant. An out-of-scope
  id returns 404.
- The response streams through the API with T2 headers and
  `Cache-Control: private, max-age=300`.
- There are **no presigned or public URLs**.

#### 6.14.4 Similar pages (clusters)

- Pages cluster per tenant when their pHash Hamming distance is ≤ 6.
- **Candidate lookup** splits the 64-bit hash into four 16-bit bands. A
  table `screenshot_phash_bands(tenant_id, band_no, band_value,
  screenshot_id)` with an index on `(tenant_id, band_no, band_value)`
  finds candidates. By the pigeonhole principle, any pair within distance
  ≤ 3 shares at least one band. Pairs at distance 4–6 are caught by a
  nightly BK-tree pass per tenant. This is the documented trade-off: new
  captures join existing clusters immediately at ≤ 3, and a daily
  reconcile catches 4–6.
- **Gallery.** `GET /api/v1/services/screenshot-clusters?q=` returns
  clusters, each with its size, a representative image, the most common
  title and the labels present. The OQL field `screenshot.cluster` lets
  any view filter to a cluster.
- **Labelling a cluster** is a bulk label over `screenshot.cluster:<id>`.
  It goes through the normal bulk-label preview.

#### 6.14.5 Retention

- **30 days**, per RFC-036 O7. The **latest** capture of each live
  service is always kept, so the gallery never empties.
- A daily job deletes expired rows and their objects. An object is
  deleted only when no row references its hash.
- Archiving a service schedules its screenshots for expiry.
- **Per-tenant quota.** The default is 5 GB. When the quota is reached,
  capture pauses with a visible warning; it does not silently evict.

### 6.15 Policy engine

#### 6.15.1 Model

Table `asset_policies`:

| Column | Notes |
|---|---|
| `id`, `tenant_id`, `name`, `description` | |
| `enabled` | default false |
| `subject` | `asset` or `service` |
| `condition` | OQL text + canonical + version |
| `triggers` | jsonb, any of:<br>• `{"on": "discover"}`<br>• `{"on": "change", "facets": ["http", "tls", "tech", "ports", "dns"]}`<br>• `{"on": "schedule", "cron": "0 3 * * *"}` |
| `apply_to` | `future` or `existing_and_future` |
| `actions` | jsonb array, ≤ 5 (§6.15.2) |
| `limits` | jsonb, defaults:<br>• `max_subjects_per_run: 1000`<br>• `max_archive_per_run: min(100, 5 %)`<br>• `max_scans_per_hour: 1` |
| `author_id`, `approved_by` | `approved_by` only for `trigger_scan` |
| `preview_hash`, `previewed_at` | |
| `state` | `active`, `paused_needs_confirmation`, `disabled_breaker` |
| `consecutive_capped_runs` | |
| `version` | |
| `created_at`, `updated_at` | |

Two log tables go with it:

- `asset_policy_runs(id, policy_id, tenant_id, trigger, started_at,
  finished_at, matched, acted, skipped, status, error, dry_run)`.
- `asset_policy_effects(run_id, subject_type, subject_id, action, before
  jsonb, after jsonb)`. It is append-only and kept 13 months, the same as
  observations. Every effect is also written to the hash-chained audit
  log as one summary entry per run, with the effect count, so the audit
  log does not grow with every label.

#### 6.15.2 Actions

| Action | Effect | Guard |
|---|---|---|
| `add_label` / `remove_label` | `label_assignments` (source `policy`, origin `policy:<id>`) + denormalised arrays; custom labels via `tags` | idempotent; `remove_label` only removes assignments **from this policy** unless `force: true` (then it needs `assets:write` checked at run time) |
| `notify` | outbox event `asset_policy_matched` to the tenant's notification integrations (Slack, Teams, email, webhook, Splunk), one digest per run, up to 50 subjects listed with a link to the run | per-channel escaping (T6) |
| `archive` | `state = archived`, `archived_reason = policy:<id>` | per-run cap (T10); reversible from the run page ("restore all from this run") |
| `mark_out_of_scope` | creates a **pending** scope exclusion for each subject (exact pattern), through the normal approval flow | never self-approves; capped at 50 per run |
| `set_criticality` | asset's own criticality (effective follows, §3.5) | only raises unless `allow_lower: true` |
| `set_owner` | the RACI primary owner in `asset_owners`, the one owner model (`assets.owner_id` was removed in 2026-10, see `architecture/asset-ownership.md`) | only when no owner is set, unless `overwrite: true` |
| `trigger_scan` | creates a scan over the matched set (`selection = {q: condition AND id in run set}`) through the gate | author holds `scans:execute` at run time; `approved_by` set by a second user with `scans:execute`, otherwise the scan is created `pending_approval`; `max_scans_per_hour`; tenant budget |

There is **no `delete` action** (§2.1).

**Identity fields (I7).** Every effect has a declared, stable identity
made only of non-volatile fields:

| What | Identity |
|---|---|
| A label assignment | `(label_id, subject_type, subject_id)` |
| An archive | `(policy_id, subject_id)` |
| A digest line | `(policy_id, subject_id, change_kind)` |
| A pending exclusion | `(policy_id, normalised pattern)` |
| A scan request | `(policy_id, canonical selection hash, hour bucket)` |

Re-running a policy on the same facts therefore produces the same
identities, so effects deduplicate and nothing comes back as "new" every
run. A future action that raises exposures or findings must declare its
`identity_fields` in the same way, for example `(policy_id, asset_id,
port)`. The fingerprint is built from those fields only, never from
titles, counts or timestamps. This avoids the stale-fingerprint class of
bug seen in the asset-merge dedup fix.

#### 6.15.3 Lifecycle

1. **Draft.** The author saves the policy; it is disabled.
2. **Preview** (`POST /api/v1/asset-policies/{asset_policy_id}/preview`,
   or `POST /api/v1/asset-policies/preview` for an unsaved body). It
   returns:
   - the match count over existing subjects;
   - 20 samples;
   - per-action effects, for example "would add *Jenkins CI* to 37
     services, 12 already have it; would archive 4";
   - whether any cap would be hit;
   - the `Explain()` sentence.

   The server stores `preview_hash` = the hash of the canonical condition,
   the actions and the limits.
3. **Enable** (`POST …/{asset_policy_id}/enable`). This is refused
   (409 `PREVIEW_REQUIRED`) unless `preview_hash` matches the current
   definition and `previewed_at` is less than 24 hours old. When
   `apply_to = existing_and_future`, enabling runs the existing-set pass
   as a normal run.
4. **Run.** It runs on its triggers, and also manually through
   `POST …/{asset_policy_id}/run`, which writes a run record.
5. **Disable** (`POST …/{asset_policy_id}/disable`). Any edit of the
   condition, actions or limits disables the policy and requires a new
   preview.

#### 6.15.4 Evaluation

- **Events.**
  - Ingest writes an `inventory_change` row in the **same transaction**
    as the observation diff (§6.16). This is the transactional-outbox
    pattern; research 02 finding 4.
  - Each row carries tenant, subject, change kinds and `origin`, which
    is `ingest`, `user:<id>`, `policy:<id>` or `exclusion:<id>`.
  - Label, archive and owner changes made by any path write the same
    row.
- **The policy worker** claims change rows with
  `FOR UPDATE SKIP LOCKED` (research 02 finding 1), in batches of 500
  per tenant. For each active policy whose trigger matches the change
  kinds, it evaluates the condition **as SQL over the batch's subject
  ids** (`compiled_condition AND id = ANY($batch)`). That is one query
  per policy per batch, never one per row.
- **Discovery vs change.** `on discover` = change kind `created`.
  `on change` = any of the listed facets changed. `future` policies
  ignore subjects created before the policy's `enabled_at`.
- **Scheduled triggers** run the condition over the whole subject set
  with keyset paging. They are leased per policy, so one replica runs
  each schedule.
- **Ordering.** Policies run in `created_at` order within a batch. All
  effects of a run are applied in one transaction per 500-subject chunk.
- **Delivery.** At-least-once; every action is idempotent, so a replayed
  batch is harmless.

#### 6.15.5 Loop and runaway protection

- **Self-origin skip.** A change with `origin = policy:<id>` never
  triggers policy `<id>`.
- **Depth.** Each change row carries `chain_depth`. A policy effect
  writes `depth + 1`, and rows with depth ≥ 3 are not evaluated by
  policies. The run records `skipped_depth`.
- **Caps.**
  - Hitting `max_subjects_per_run` or the archive cap stops the run
    before any effect beyond the cap. The policy then goes to
    `paused_needs_confirmation`, and its owner gets an in-app
    notification and the outbox event.
  - A human resumes it with
    `POST …/{asset_policy_id}/enable {acknowledge_cap: true}`.
- **Breaker.** Three capped runs in a row set `disabled_breaker` and
  notify the owner.
- **Tenant ceiling.** At most 50 enabled policies per tenant (settable by
  the admin console), and at most 10,000 effects per tenant per hour
  across all policies. Over the ceiling, runs queue; they are not
  dropped.

#### 6.15.6 Relationship to workflows

- Workflows remain the graph-based automation for findings and
  tickets.
- Policies do not live inside workflows. Policies are **set-based** (one
  SQL condition over many rows). They need preview, apply-to-existing,
  per-run caps and reversible effects. Workflows run once per event with
  a payload of at most 100 assets
  (`api/internal/app/workflow/event_dispatcher_discovery.go:16`) and have
  no loop protection (F20).
- A policy can feed a workflow through the existing `asset_discovered`
  trigger or the new `asset_policy_matched` outbox event, so the
  imperative steps stay in workflows.
- D6 asks the owner to confirm this split.

### 6.16 Observations and change detection

**One table.** This is RFC-036 §6.5's `easm_observations`, renamed
`inventory_observations` because it covers internal assets too, with the
subject widened to services:

```
inventory_observations(id, tenant_id, subject_type asset|service, subject_id,
    facet dns|ports|http|tls|tech|rdap|screenshot, hash bytea, value jsonb (canonical),
    first_seen, last_seen, source_run_id, sensor_id NULL)
  index (tenant_id, subject_type, subject_id, facet, last_seen DESC)
```

- The name is settled once (D4). If RFC-036 P4 has already shipped
  `easm_observations` by then, this phase renames it and adds the subject
  columns.
- Ingest canonicalises each facet before hashing: sorted RRsets, a sorted
  port set, HTTP `{status, title, server, favicon, tech set with
  versions}`, the TLS leaf fingerprint and SANs, and the tech set.
- **Unchanged hash:** update `last_seen` on the latest row, plus the
  subject's `last_seen`.
- **Changed hash:** insert a row, update the typed columns on the subject,
  set `last_changed_at`, and write the `inventory_change` (§6.15.4).
- **Run tags (I5).** Assets, services and source records carry
  `last_seen_run_id`. "New" means `first_seen` falls within this run.
  "Gone" is decided **only inside the scope the run covered**: the run's
  resolved targets, ports and zone, recorded on `scan_run_targets`. For
  example, a service the run did not see on a host it did scan, on a
  port range it did scan. A run that failed or was cancelled part-way
  marks nothing gone: cleanup never follows a failed fetch. Gone means `state = closed` for a service and `stale`
  for an asset, through the lifecycle worker. It never means a delete.

**Change kinds** (derived from the facet diff):

| Kind | From facet | Becomes |
|---|---|---|
| `asset_created`, `service_created` (new port) | insert | outbox `new_asset` / `new_service`; exposure event `port_open` (RFC-036) |
| `service_closed` | ports facet lost the port in **2 consecutive** observations (flap guard) | `port_closed`; service `state = closed` (not archived) |
| `cert_changed` | tls | exposure `certificate_*` (RFC-036) |
| `cert_expiring` | tls, scheduled (30/14/7/1 days before `tls_not_after`) | outbox `certificate_expiring` (existing CT path dedups by fingerprint) |
| `tech_added`, `tech_removed`, `tech_version_changed` | tech | outbox `asset_changed` (finally produced, F21) |
| `title_changed`, `status_changed`, `server_changed` | http | `asset_changed` |
| `dns_changed` | dns | exposure `dns_change` (RFC-036) |
| `screenshot_changed` | screenshot (pHash distance > 10) | `asset_changed` |

- **Notifications.** Alerts are **per-tenant digests**, not one message
  per change. The existing `new_asset` throttle moves from process memory
  into the outbox: one pending digest row per tenant and kind, so N API
  replicas no longer send N digests (F21).
- **Subscriptions.** A tenant subscribes per kind and per OQL filter on
  its notification integration, for example "only `is.public:true
  criticality>=high`". The filter is stored as OQL; the dispatcher
  evaluates it with the compiler over the digest's subjects.
- **Retention.** Changed rows are kept 13 months (RFC-036 O7). A monthly
  job deletes older rows, keeping the latest row per (subject, facet).

### 6.17 Rollups, trends and distributions

The owner's design screenshots (Overview, Dashboard, Asset Groups) need:

- trends: exposed assets, services and technologies over time;
- top-10 distributions (asset types, domains, technologies) with export;
- counts per auto label;
- "affected services";
- groups as discovery runs (§6.12);
- template-triggered checks.

**Table `inventory_daily_rollups`:**

| Column | Notes |
|---|---|
| `tenant_id` | |
| `day` | date, tenant time zone |
| `metric` | text |
| `dimension` | text, `''` for totals |
| `value` | bigint |
| `computed_at` | |
| primary key | `(tenant_id, metric, dimension, day)` |

**Metrics:**

| Metric | Dimension | Notes |
|---|---|---|
| `assets_live` | type | |
| `assets_exposed` | `''` | public / internet-accessible |
| `services_live` | `''`, port, scheme | |
| `technologies_distinct` | `''` | |
| `services_by_tech` | technology slug | |
| `services_by_label` | label key | "asset categories" |
| `affected_services` | severity | services with ≥ 1 open finding (§6.4.4) |
| `new_assets`, `new_services`, `closed_services` | `''` | from changes |
| `certs_expiring_30d` | `''` | |

- **Computation.** A nightly controller computes the rollups after
  midnight in the tenant's time zone, leased per tenant. They come from
  the live tables (counts) and from `inventory_change` (flows). They are
  idempotent: an upsert per (tenant, metric, dimension, day).
- **Retention.** Daily rows for 400 days, then monthly aggregates kept
  indefinitely, in the same table with `day` set to the first of the
  month. The `metric` suffix `@month` marks them.
- **No backfill from before observations existed.** A trend starts on
  the day its inputs started.

**Endpoints:**

- `GET /api/v1/inventory/trends?metrics=assets_exposed,services_live&from=&to=&dimension=`
- `GET /api/v1/inventory/distributions?field=tech|type|domain|label&q=&size=10`.
  This is the facet engine, so it honours data scope and `q`. Export
  goes through the services export with `group_by`.

**Honest-numbers contract.** Every metric value in these responses has
this shape:

```json
{ "metric": "assets_exposed", "points": [ { "day": "2026-10-01", "value": 812 } ],
  "status": "ok" | "insufficient_data" | "partial",
  "reason": "no_observations_before_2026-09-20" }
```

- `insufficient_data`: no input rows for the window, for example before
  the first rollup, or when no sensor has ever run httpx. The UI shows
  "insufficient data", never 0.
- `partial`: some days in the window are missing; those days are listed.
  A day is never interpolated.
- **Data scope on trends.** Rollups are per tenant. A data-scoped user
  sees trends only if `inventory.trends_for_scoped_users = true`, in
  which case they see tenant-wide numbers and are told so. Otherwise
  they get `insufficient_data` with `reason: data_scope`; D9 decides the
  default. Distributions and facets are always computed live for scoped
  users.

**Template-triggered checks** (research 01b R2, "new checks published in
the last 7/30 days, and how many of our services were checked against
them"):

- Sensors already report their nuclei-templates content version through
  the RFC-033 manifest. Under RFC-031, they will also report the
  template index diff for each content update.
- **New table** `content_releases(tenant_id NULL, kind 'nuclei_templates',
  version, released_at, added_template_ids text[] (capped 5000),
  added_count)`. It is filled from the manifest or content reports.
- "Services checked against new templates" =
  `count(DISTINCT service_id)` over scan runs since `released_at` whose
  recorded content version is ≥ that release and whose tool is nuclei.
  This needs `scan_runs` to record the content version per tool, a small
  RFC-031 addition.
- Until both inputs exist, the endpoint returns `insufficient_data` with
  `reason: content_versions_not_reported`. Owner rule: no placeholder.

### 6.18 API summary

These follow [RFC-041](RFC-041-api-path-design.md):

- `{snake_case_id}` path parameters;
- the closed verb list;
- `POST /{collection}/bulk/{verb}`;
- `page`/`per_page`, plus `cursor` for exports;
- the `pkg/apierror` envelope, with RFC 9457 on `Accept`.

Module: inventory routes stay ungated, as today; EASM-only parts stay
under `attack_surface` (RFC-036 O10).

| Route | Permission | Phase |
|---|---|---|
| `GET /api/v1/asset-types` (classes, types, attribute schemas, facets, renderers, sections, relationships, identity keys, lenses; ETag) | `assets:read` | P0 |
| `GET /api/v1/assets` gains `q`, `lens`, core counters and `asset_class`; `GET /api/v1/assets/facets` per class | `assets:read` + data scope | P0 |
| `GET /api/v1/assets/{asset_id}/paths` (`to_class`, `to_asset_id`, `max_depth` ≤ 8) | `assets:read` + data scope at every hop | P3 |
| `GET /api/v1/services` (`q`, `sort`, `page`, `per_page`, `cursor`) | `assets:read` + data scope | P0 |
| `GET /api/v1/services/{service_id}` (+ `findings_summary`, lineage, latest observations) | `assets:read` | P0 |
| `GET /api/v1/services/facets`, `GET /api/v1/assets/facets` (v2 contract; `?legacy=1` for one release) | `assets:read` | P0 |
| `GET /api/v1/services/groups` | `assets:read` | P0 |
| `POST /api/v1/services/exports`, `GET /api/v1/services/exports/{export_id}` (and `/assets/exports`) | `assets:export` | P0 |
| `POST /api/v1/oql/validate` (`{q, subject}` → canonical, explain, errors) | `assets:read` | P0 |
| `GET/POST /api/v1/saved-filters`, `GET/PATCH/DELETE /api/v1/saved-filters/{saved_filter_id}` | `assets:read` (own), `assets:write` (tenant-visible) | P0 |
| `GET /api/v1/labels`, `POST /api/v1/labels`, `PATCH/DELETE /api/v1/labels/{label_id}` | `assets:read` / `assets:write` | P0 |
| `POST /api/v1/label-assignments/preview`, `POST /api/v1/label-assignments` (`{label_ids, op: add\|remove, selection: {q\|ids}, subject}`; ≤ 10,000 subjects; async above 1,000 → 202) | `assets:write` | P0 |
| `GET /api/v1/technologies`, `GET /api/v1/technologies/{technology_id}`, `GET /api/v1/technologies/{technology_id}/icon` | `assets:read` | P0 |
| `PATCH /api/v1/asset-groups/{asset_group_id}` (kind, query, cadence…), `POST /api/v1/asset-groups/preview` (`{query}` → counts) | `assets:groups:write` | P0 |
| `POST /api/v1/scans/preview`; `POST /api/v1/scans` gains `selection` + `preview_token` | `scans:execute` | P0 |
| `GET /api/v1/inventory/distributions` | `assets:read` | P0 |
| `GET/POST /api/v1/asset-policies`, `GET/PATCH/DELETE /api/v1/asset-policies/{asset_policy_id}` | `assets:policies:read` / `assets:policies:write` (new) | P1 |
| `POST /api/v1/asset-policies/preview`, `POST /api/v1/asset-policies/{asset_policy_id}/preview\|enable\|disable\|run\|approve` | `assets:policies:write`; `approve` needs `scans:execute` and ≠ author | P1 |
| `GET /api/v1/asset-policies/{asset_policy_id}/runs`, `GET /api/v1/asset-policy-runs/{run_id}` (+ effects, cursor) | `assets:policies:read` | P1 |
| `POST /api/v1/assets/bulk/reactivate`, `POST /api/v1/services/bulk/reactivate` (`selection: {ids \| q \| policy_run_id}`) — restore archived subjects | `assets:write` | P1 |
| `POST /api/v1/assets/bulk/status` gains `selection.q` (bulk status by filter); `POST /api/v1/services/bulk/status` | `assets:write`; archive also needs a preview token like scans | P0 |
| `POST /api/v1/scope/exclusions/preview` | `attack_surface:scope:read` | P1 |
| `POST /api/v1/assets/{asset_id}/split` (`{source_record_ids[]}`; D17) and `GET /api/v1/assets/{asset_id}/sources` (layer-1 records with `linked_by`) | `assets:write` / `assets:read` | P1 |
| `GET /api/v1/inventory/changes` (`q`, `kinds`, `from`, `to`, `cursor`) | `assets:read` | P1 |
| `GET /api/v1/inventory/trends` | `assets:read` | P1 |
| `GET /api/v1/services/{service_id}/observations` (`facet`, `cursor`) | `assets:read` | P1 |
| `POST /api/v2/sensor/screenshots` (sensor plane, v2 feature `screenshots`) | sensor key bound to the run | P2 |
| `GET /api/v1/services/{service_id}/screenshots`, `…/{screenshot_id}/image` | `assets:read` + data scope | P2 |
| `GET /api/v1/services/screenshot-clusters` | `assets:read` | P2 |
| `GET /api/v1/assets/{asset_id}/lineage` | `assets:read` | P3 |
| `GET /api/v1/inventory/content-checks` (template-triggered) | `assets:read` | P4 |

**Restoring a run's archive.** "Reopen" and "restore" are not in
RFC-041's closed verb list, so the restore is a collection-wide bulk
action with the existing `reactivate` verb:
`POST /api/v1/assets/bulk/reactivate {selection: {policy_run_id}}`. The
vocabulary does not grow. The same applies to labels: "label" is not a
verb, so a bulk label is the creation of `label-assignments`, a resource.

**New permissions:** `assets:policies:read` and `assets:policies:write`,
given to owner and admin by default (member gets read). Label writes reuse
`assets:write`. Exports reuse `assets:export`. Screenshots reuse
`assets:read`.

### 6.19 UI

The companion document (`web/docs/ui/inventory-integrations-2026-10.md`,
and its HTML mock with the tabs Inventory / Groups / What changed /
Suggestions / Policies) owns layout and components. This
RFC fixes the contracts that the UI relies on:

- **Lenses, not one list.** The inventory opens on **All assets** (core
  columns + a compact type-aware cell). Lens tabs come from the registry
  (§6.3.6). The service card below is the **External surface** lens only;
  Code, Cloud, Containers, Identities, Data and Network render their own
  registry-declared cards and columns. Each lens keeps facets, group-by,
  bulk actions and saved views.
- **No per-type page code.** Columns, cards, facets and detail sections
  render from `GET /api/v1/asset-types`. The web holds a closed set of
  named renderers; adding a type is a YAML entry plus, at most, one new
  renderer.

- **Service card fields.** Every chip on the card maps to a §6.4.1
  column:
  - favicon (by `favicon_mmh3`; icon bytes are never fetched from the
    target);
  - `host:port`, status, ASN, IP, CNAME;
  - labels with a source dot (system or custom) and tech chips with
    icon and version;
  - TLS expiry and issuer;
  - screenshot thumbnail and title;
  - last seen;
  - "Issues found" (`open_finding_count`, `max_open_severity`), linking
    to findings with `service_id`.
- **The filter bar edits OQL.** The facet menu builds OQL clauses, and
  power users type OQL. Both show the `Explain()` sentence.
- **Group-by chips** call `/services/groups`. Each group header offers
  Export and "Scan this group", which opens the preview result (§6.11).
- **Counts display.** Every count renders `exact:false` as "≥ n" or
  "n+", and `insufficient_data` as a dash with a tooltip.

## 7. Performance targets

| Operation | Data | Target (p95, warm cache, 4 vCPU / 16 GB Postgres) |
|---|---|---|
| Service list page, ≤ 5 clauses, default sort | 100k services / tenant | ≤ 300 ms |
| Same | 1M services / tenant | ≤ 800 ms |
| Facets, 8 fields, filtered | 100k | ≤ 600 ms; per field ≤ 1.5 s hard timeout, lower bound beyond |
| Facets, unfiltered (snapshot) | any | ≤ 50 ms; staleness ≤ 60 s after the last change |
| Group-by page (20 groups × 5 items) | 100k | ≤ 600 ms |
| Leading-wildcard host/title search (`*foo*`, trigram) | 1M | ≤ 1 s |
| Dynamic group resolve at dispatch | 10k members | ≤ 2 s (keyset, gate included) |
| Gate check at claim time | per chunk of 100 | ≤ 20 ms |
| Policy on-change latency (ingest commit → effect) | batch of 500 | ≤ 10 s |
| Scheduled policy over all subjects | 100k | ≤ 60 s |
| Bulk label via query | 10k subjects | ≤ 5 s (async job beyond 1,000) |
| Export | 100k rows CSV | ≤ 60 s, streamed with cursor |
| Ingest overhead of observations + services upsert | per batch | ≤ +15 % vs today |
| Observation growth | steady state | ≤ 1.5 rows / service / month (median) |
| Screenshot | per capture | ≤ 20 s hard; median ≤ 150 KB stored |

**How we hold this:**

- A synthetic-tenant fixture generator (`api/tests/perf/inventory`)
  builds 100k and 1M services with realistic distributions: Zipf
  technologies, a long tail of ports, 30 % TLS.
- `EXPLAIN (ANALYZE, BUFFERS)` guard tests fail when a registry field's
  query does a sequential scan on `asset_services` at 100k.
- A k6 load test against the list, facets and groups endpoints runs
  nightly on `develop` and gates P0's acceptance.

## 8. Compatibility and migration

All migrations are additive, in this order:

1. New service columns, nullable.
2. New tables: `technologies`, `technology_categories`,
   `service_technologies`, `labels`, `label_assignments`,
   `saved_filters`, `inventory_facet_counts`, `inventory_daily_rollups`,
   then (later phases) `asset_policies*`, `inventory_observations`,
   `inventory_change`, `service_sources`, `discovery_edges`,
   `service_screenshots`,
   `screenshot_phash_bands` and `content_releases`.
3. `findings.service_id`.
4. `asset_groups` columns.
5. `scope_exclusions` columns.

Indexes are created `CONCURRENTLY` in separate migrations. golang-migrate
runs each file outside a transaction when the file opts in, which is the
pattern already used for large indexes.

**Backfills** are resumable jobs, not migrations: services from
service-type assets and `properties.ports`, DNS columns, technologies,
`findings.service_id` and the tag clean-up. Each job:

- records progress in `asset_identity_backfill`-style state (`000243`);
- is idempotent;
- logs counts of rows it could not map.

The development API container hot-reloads with air, which does not apply
migrations, so every phase's PR states the manual migrate step.

**API compatibility:**

- `/api/v1/assets` query parameters keep working (§6.5.3).
- `/api/v1/services` keeps its fields and adds new ones.
- `/assets/facets` keeps the legacy shape under `?legacy=1` for one
  release, with deprecation headers per RFC-041 §7.

**Merge plan:** the new FK columns join `asset_merge_plan.go`, and the
coverage test enforces them (F8).

**RLS:** each new table gets a shadow policy like the existing 99, so
the RLS rollout plan (`api/docs/architecture/rls-rollout.md`) still
covers it.

**Rollback:** each phase is behind a tenant setting. `inventory.v2_ingest`
switches between writing services and creating service-type assets. The
web reads v2 endpoints only when the API advertises them in `/api/v1/me`
capabilities.

## 9. Phased plan

Effort is in engineer-weeks across all repositories.

### P0: Type registry, services, query, facets, groups, bulk labels (highest value, least work): 6–7

**Migrations:**

- `asset_types.class` (seeded from `api/configs/asset-types.yaml`) and the denormalised, indexed `assets.asset_class`;
- `asset_services` columns and indexes (§6.4);
- `assets` DNS columns and `apex_domain`;
- `findings.service_id`;
- `technologies`, `technology_categories`, `service_technologies`;
- `labels`, `label_assignments`;
- `saved_filters`;
- `inventory_facet_counts`;
- `asset_groups` `kind`/`subject`/`query`/`oql_version`/`origin`/`cadence`/counts;
- `asset_group_service_members`.

P0 adds no permissions; it reuses `assets:*`, `assets:groups:*`,
`assets:export` and `scans:execute`.

**API:**

- the type registry: `asset-types.yaml`, `make generate-asset-types` (Go + TS), the `asset-types-drift` CI check, and `GET /api/v1/asset-types`;
- attribute validation against the registry on ingest and on asset writes, with unknown keys quarantined;
- the OQL package: parser, field registry generated from the core plus the type registry, compiler, `Explain`, fuzz tests;
- the services list, detail, facets, groups and exports, and
  `oql/validate`;
- saved filters, labels, label assignments (preview + apply) and
  technologies;
- asset-group preview and dynamic groups at dispatch;
- `scans/preview` and `selection`;
- the target gate, extracted from `resolveScanTargets`. It is applied at
  trigger, pipeline `context.targets` and the coverage dispatcher, which
  closes F16 except claim-time;
- facets and stats honour data scope (F10);
- ingest writes services (`UpsertBatch`'s first caller), technologies and
  `service_id`;
- the backfill jobs;
- the technology catalog import CLI.

**sdk-go / ctis / sensor:**

- the ctis `http` block and TLS leaf fields;
- stop copying technologies into tags (F3);
- the sdk-go httpx parser keeps favicon, JARM, ASN, CDN and TLS (F4);
- the sensor passes the httpx flags (§6.9). This depends on RFC-036
  P0 E2, which ships the binaries.

**Web:**

- Inventory with lens tabs from the registry: **All assets** (core columns + type-aware cell) and **External surface** (service cards, the OQL filter bar, facet counts and group-by);
- saved filters;
- the bulk label bar as one call;
- the "Scan this selection/group" dialog with preview;
- dynamic group create and edit, with preview counts;
- the technology chips and catalog.

**Acceptance:**

- On the 100k fixture: §7 list, facet and group targets met.
- A scoped user's facet total equals their list total.
- A dynamic group scan skips archived, excluded and unconfirmed targets
  and reports each reason.
- Hostile-title fixture: no script runs.
- Two-tenant isolation tests pass for every new endpoint.

### P1: Policies, observations, change alerts, exclusions everywhere: 4–5

**Migrations:**

- `asset_policies`, `asset_policy_runs`, `asset_policy_effects`;
- `inventory_change`;
- `inventory_observations`, renamed from or replacing RFC-036
  `easm_observations` (D4);
- `inventory_daily_rollups`;
- `scope_exclusions` `applies_to`/`pattern_kind`/`effect`/`exclusion_kind`,
  plus the `*.x` rewrite;
- `asset_services` `archived_reason`;
- `service_sources`;
- `asset_sources` gains `tenant_id`, `last_seen_run_id`, `linked_by`,
  `linked_at` and `linked_run_id`, plus the `asset_links` view;
- `last_seen_run_id` on assets and services;
- the zone id in RFC-028 identity keys for private addresses (D16);
- the generated partial expression indexes for registry facet attributes
  (one migration per registry change, created `CONCURRENTLY`);
- `saved_filters.lens`;
- the `assets:policies:*` permissions.

**API:**

- the policy engine: preview, enable, caps, breaker, worker, scheduler,
  audit;
- the facet hashing and change kinds in ingest;
- outbox digests (moving the `new_asset` throttle out of memory) and
  `asset_changed` produced;
- the exclusion preview, the archive job and un-archive;
- exclusions at ingest and in CT discovery;
- the gate at RFC-030 claim time;
- trends and changes endpoints;
- the "affected services" metric;
- the correlation job (single-flight per tenant and zone, §6.4.5):
  windowed match proposals, the preferred-field recompute and the
  snapshot;
- gone detection limited to the run's scope;
- asset split (D17), with audit;
- the OQL `source:` scope and `facets?source=`.

**Sensor:** none. The sensor-side scope check (RFC-023 D7/D8) still
applies after resolution; claim-time gating is on the API.

**Web:**

- Policies tab: list, editor with OQL and actions, preview, runs and
  effects, restore;
- What changed, on the new change kinds;
- trend charts with `insufficient_data` states;
- exclusion preview in the request and approval dialogs;
- the remaining lenses (Applications, Cloud & infrastructure, Containers & Kubernetes, Code, Identities, Data, Network), from the registry. The 25 per-type `config.tsx` pages are folded in one class at a time and their URLs 308-redirect to lens presets.

**Acceptance:**

- A policy that would archive the whole inventory pauses with zero
  effects.
- Two mutually-triggering policies stop at depth 3.
- Rotating a fixture certificate yields exactly one `cert_changed` and
  one alert digest.
- Approving `*.staging.acme.com` archives matching assets and their
  only-through descendants; removing it restores them.

### P2: Screenshots and system labels: 4

**Migrations:**

- `service_screenshots`, `screenshot_phash_bands`;
- system rule-set seed rows in `labels`.

**Sensor:**

- `octm-shot` with the T3/T4 controls;
- the `screenshots` v2 feature;
- the manifest capability `screenshot`;
- the body keyword hits for label rules.

**API:**

- upload, re-encode and store;
- serving with T2 headers;
- clusters (bands + nightly BK-tree reconcile);
- retention and quota jobs;
- the label engine, rule set v1 and backfill on version bump;
- the cluster bulk-label path.

**Web:**

- Screenshots tab (gallery by cluster);
- thumbnails on cards;
- the label source and evidence drawer.

**Acceptance:**

- The SSRF fixtures (metadata redirect, `file://`, rebinding) are blocked
  and logged.
- Polyglot and SVG uploads are refused.
- Identical pages dedupe.
- After 30 days only the latest capture per service remains.
- Each v1 rule has a positive and a negative fixture.

### P3: Associated domains and lineage in the inventory: 3 (after RFC-036 P2)

**Migrations:**

- `discovery_edges`;
- the evidence fields `subsidiary_of` and the subsidiaries list
  (`easm_subsidiaries`: tenant, name, acquisition date, source URL).

**API:**

- lineage writes from ingest and pipeline hops;
- `GET /assets/{asset_id}/paths`: a recursive CTE over the relationship types the registry marks `traversable`, with data scope at every hop;
- the `serves` and `serves_certificate` relationship types; the `service_id` qualifier on `asset_relationships` (joins the merge plan); repository edges from container image source labels;
- `GET /assets/{asset_id}/lineage`;
- graph-cut reachability in the exclusion job;
- candidate enrichment (reachability, subdomain count).

**Sensor / sdk-go:** each pipeline step's CTIS output stamps the parent
asset or seed it was derived from, so ingest can write lineage edges.

**Web:**

- the "How was this found?" drawer;
- the "Attack surface to code" path view on service, application and repository drawers;
- Suggestions tab showing candidate evidence fields, reusing RFC-036's
  Review tab.

**Acceptance:**

- Excluding a parent archives descendants with no other path, and keeps
  those with one.
- Every inventoried external asset has at least one lineage edge or is
  marked `manual`.

### P4: Rollup extras and template-triggered checks: 1.5 (after RFC-031 content reports)

- **Migrations:** `content_releases`; a content-version column on
  `scan_runs` per tool.
- **API:** `GET /api/v1/inventory/content-checks` and the writer that
  fills `content_releases` from manifest and content reports.
- **Sensor:** report the nuclei-templates index diff with each RFC-031
  content update.
- **Web:** "New checks published in the last 7/30 days" and "services
  checked against them" on the inventory overview.

These report `insufficient_data` until sensors report content diffs.

### Dependencies and order

P0 can start now in parallel with RFC-036 P1. Services are useful as soon
as httpx data arrives, which depends on RFC-036 P0 E2. P1's observation
table must be agreed with RFC-036 P4 (D4). P3 waits for RFC-036 P2.

### 9.1 P0 work breakdown

P0 ships as seven PR slices to `develop`, in order. Each slice merges on
its own and leaves `develop` working. Migration numbers are taken at
implementation time, after the ones open PRs reserve (000273–000327).
Every slice that adds a table referencing `assets` also updates
`asset_merge_plan.go`, which the coverage test enforces.

| # | Slice | Depends on | Migrations | Scope |
|---|---|---|---|---|
| 1 | **Type registry** | — | `asset_types.class` and `asset_types.lens`, seeded from the YAML; `assets.asset_class` and `assets.asset_lens` columns with a batched backfill from `asset_type`, an index, and the trigger that keeps them in sync | `api/configs/asset-types.yaml` covering all 37 types in 16 classes and 8 lenses (§6.3.2–6.3.3); `make generate-asset-types` (Go + TS); `asset-types-drift` CI check; `GET /api/v1/asset-types`; attribute validation on write, with unknown keys quarantined (§6.3.3); `category.go` generated |
| 2 | **Services** | 1 (class `service`) | `asset_services` new columns, the key change to `(tenant_id, asset_id, port, transport)`, and indexes created `CONCURRENTLY` (§6.4.1–6.4.3); `assets` DNS columns and `apex_domain`; `findings.service_id` and its partial index | ingest upserts `host:port` rows (`UpsertBatch`'s first caller) instead of `service`-type assets, behind the `inventory.v2_ingest` setting; counters on finding transitions; resumable backfill jobs (§6.8); `GET /services` gains the new fields; ctis `http` block + TLS fields; no more tech-to-tags copying; the sdk-go httpx parser keeps all fields |
| 3 | **OQL, facets, group-by** | 1, 2 | `inventory_facet_counts`; trigram and GIN indexes from §6.4.3 not created in slice 2 | `internal/app/oql`: parser, field registry generated from the core plus the type registry, compiler that injects tenant and data scope and binds every value, limits and timeouts, `Explain`, fuzz tests; `q` on `/assets` and `/services`; `/services/facets` and the v2 `/assets/facets` (data scope fixes F10); `/services/groups`; `/oql/validate`; exports (`/services/exports`, `/assets/exports`); EXPLAIN guard tests and the 100k fixture |
| 4 | **Saved filters, dynamic groups, bulk labels** | 3 | `saved_filters`; `asset_groups` gains `kind`, `subject`, `query`, `oql_version`, `origin`, `cadence`, run fields and counts; `asset_group_service_members`; `labels`, `label_assignments`; `system_labels` arrays | saved-filter CRUD; dynamic-group create/preview, with dispatch-time expansion handed to slice 5; `/labels`; `/label-assignments/preview` and apply by selector (`q` or ids), async above 1,000; bulk status by `q` |
| 5 | **Target gate** | 1, 3 (selectors), 4 (dynamic groups) | none required (exclusion model changes are P1) | `scope.Gate`, extracted from `resolveScanTargets` and checking archived, attribution, exclusions by name, aliases and resolved IPs, tier, type via the registry's `scannable_by`, and caps; used by scan trigger, `POST /pipelines/runs` targets, pipeline hops, quick scans and the coverage dispatcher; `POST /scans/preview` with `preview_token`; `POST /scans` with `selection`. The RFC-030 claim-time re-check lands here as a call site if RFC-030 claim is merged; otherwise it is a P1 item |
| 6 | **Web lenses** | 1, 3; uses 4–5 when present | none | inventory shell with lens tabs from `/asset-types`; **All assets** (core columns + type-aware cell); **External surface** (service cards, OQL bar, facet counts, group-by, per-group export and scan with preview); the closed renderer set; saved views; bulk label bar as one call; old `/assets/<type>` URLs redirect where a lens covers them. Follows the companion UI doc |
| 7 | **Technology catalog** | 2 | `technology_categories`, `technologies`, `service_technologies`; `asset_services.technology_ids` | `openctem-admin catalog import webappanalyzer --tag`, plus `NOTICE` attribution; name/version split and slug resolution in ingest; `version_key` comparisons in OQL (`tech.version<3.5`); `/technologies` endpoints and the icon route; tech facet and group-by switch from the raw array to catalog ids |

**Order and parallelism:**

- 1 → 2 → 3 is the spine.
- 7 can start after 2, in parallel with 3.
- 4 follows 3, and 5 follows 4.
- 6 can start on mocked endpoints after 1 and ships after 3. Its lenses
  light up group-by, scan and saved views as 4 and 5 land.

**Acceptance per slice:**

- Each slice carries its share of the P0 acceptance list in §9.
- Slice 3 owns the §7 performance targets.
- Slice 5 owns the gate test matrix (T12).

## 10. Capabilities summary

| Capability | OpenCTEM v2 |
|---|---|
| Scan a dynamic group | yes, resolved at dispatch through the ownership gate, exclusions and budgets, with a preview of what is skipped and why |
| Exclusions | discovery + dispatch + graph cut; archived with reason, reversible, approved by a second person |
| Policies | AND/OR/NOT; archive not delete; preview required; caps, depth limit, breaker; audited effects with one-click restore |
| Associated domains | confidence from independent evidence, review queue, tombstones, no cap |
| Labels | rule version, evidence and confidence per assignment; re-evaluated on rule upgrades |
| Screenshots | documented sandbox, re-encoding, CSP, retention, quota; similar-page clusters drive bulk labels |
| Context | services tied to ownership, BU/service criticality, crown jewels, attribution, findings with P0–P3 priority |
| Breadth | 37 types in 8 classes (cloud, Kubernetes, code, identities, data, network …) with one registry and a lens per class |
| Attack surface to code | typed path from domain → IP → service → app → load balancer → workload → container → repository, with findings at each hop |
| Numbers | every count exact, lower-bound or snapshot-dated; `insufficient_data` instead of zeros |
| Hosting | self-hosted, GPL-3.0 |

## 11. Alternatives considered

| Alternative | Why not |
|---|---|
| Keep services as assets of type `service` | Every inventory count, dashboard and scope rule would mix hosts and ports. Services have different identity (host + port) and different lifecycle (they close and reopen). The services table already exists and is FK-safe in the merge plan |
| Facets over `assets.properties` JSONB (today) | Full JSONB expansion per request; no typing; cannot be indexed per value at 100k+ (F10) |
| Elasticsearch / OpenSearch for search and facets | Another stateful service to run, secure and keep consistent per tenant; Postgres with typed columns, trigram and GIN should meet §7 at the target sizes. Revisit above 5M services per tenant. **This is our own reasoning:** research 08 found no verified evidence comparing storage engines, so the P0 performance tests decide |
| ClickHouse for observations / Neo4j for lineage | Same reasoning, also unverified by research 08. Observations are change-only and small; lineage depth is capped at 8 and fits a recursive CTE. Revisit if the P1/P3 tests miss §7 |
| Probabilistic (ML) record merging | Research 08 "avoid": opaque merges cannot be explained or reversed. RFC-028's deterministic order + review stays |
| Materialised views for facets | `REFRESH MATERIALIZED VIEW` is all-tenants and heavy; a per-tenant table refreshed on change is cheaper and states `as_of` |
| Lucene / KQL-compatible syntax | Bigger grammar, regex and fuzzy operators we would have to refuse; OQL keeps search-box ergonomics with a typed registry |
| Policies as workflows | Workflows are per event, per finding, without preview, apply-to-existing or caps (§6.15.6) |
| Hard-delete action | Irreversible, and breaks finding history; archive + restore covers the use |
| Store screenshots as sent by the sensor | A compromised sensor or a hostile page could deliver polyglots; re-encoding is cheap |
| gowitness | Viable as a separate GPL executable (D7), but its request interception cannot enforce the per-zone private-range policy |
| Separate tag and label systems | Scope and assignment rules depend on tags; keeping tags as custom labels avoids breaking them |

## 12. Owner decisions (recommendations in bold)

> **Approved 2026-10-03.** The owner approved D1–D21 **as recommended**.
> The bold recommendation in each row below is now the decision. The
> other options are kept as a record of what was considered.

| # | Question | Options | Recommendation |
|---|---|---|---|
| **D1** | Where services live | (a) evolve `asset_services`; (b) new `services` table; (c) keep service-type assets | **(a).** Already FK-safe in the merge plan and exposed at `/api/v1/services`; ingest simply never wrote it |
| **D2** | Custom labels storage | (a) keep `tags` arrays as custom labels, provenance table for system/policy; (b) move everything to `label_assignments` | **(a).** Scope rules and assignment rules key on `assets.tags`; (b) means rewriting both engines for no user-visible gain |
| **D3** | Legacy service-type assets after backfill | keep hidden / archive / delete | **Keep, hidden by default view, labelled `legacy-service`.** Findings and history stay intact; revisit after two releases |
| **D4** | Observation table name and ownership | `easm_observations` (RFC-036) / `inventory_observations` | **`inventory_observations`, one table for internal and external, subject asset or service.** RFC-036 P4 builds on it rather than a second table |
| **D5** | Policy `trigger_scan` default | needs a second approver / author alone / not offered | **Second approver** (four eyes), else the scan is created `pending_approval`; max 1 scan per policy per hour |
| **D6** | Policies vs workflows | separate engine / inside workflows | **Separate, set-based engine**; workflows stay for findings; a policy can emit an event that starts a workflow |
| **D7** | Screenshot engine | (a) in-house `octm-shot` on chromedp; (b) gowitness as a separate executable | **(a)**, because the private-range interception and resolver pinning must be enforceable |
| **D8** | Screenshot retention and quota | 30 days (RFC-036 O7) + latest always kept; 5 GB per tenant | **As stated**; quota pauses capture visibly, never evicts silently |
| **D9** | Trends for data-scoped users | tenant-wide with a notice / `insufficient_data` | **`insufficient_data` by default**, tenant setting to show tenant-wide trends with a notice |
| **D10** | Technology catalog source and icons | webappanalyzer (GPL-3.0, compatible with our GPL-3.0) with icons / without icons / own table only | **webappanalyzer data + icons, pinned per release, attributed in NOTICE**, monogram fallback, tenant toggle to hide icons |
| **D11** | Exclusion `*.x` migration | rewrite to (`x`, `*.x`) / change meaning silently | **Rewrite to the pair**, audited, so behaviour of existing rows is unchanged |
| **D12** | Excluded names at ingest from tenant-triggered scans | create archived / drop | **Create archived with reason** (visible decision); discovery-source names are dropped and counted |
| **D13** | Subsidiaries (acquisitions) source | tenant-entered list + tenant-key integrations / scraped databases | **Tenant-entered list and tenant-key integrations only**; never auto-confirm from it |
| **D14** | Policy ceilings | 50 enabled policies; 10k effects/hour; archive cap min(100, 5 %) | **As stated**, admin-console adjustable per tenant |
| **D15** | Where correlation runs (I3) | (a) all inline at ingest (today); (b) all in a batch job; (c) inline strong-key match + single-flight batch job per tenant and zone for windowed matches, preferred fields and the snapshot | **(c).** Findings need an asset id at ingest time; everything fuzzy or expensive moves to the batch job, which can be re-run and audited |
| **D16** | Zone boundary for identity (I4) | private addresses keyed by (zone, address) / tenant-wide | **(zone, address) for RFC 1918/ULA/CGNAT; tenant-wide for public addresses and DNS names.** Two zones with overlapping 10.0.0.0/8 stay two assets |
| **D17** | Manual split | add `split` to RFC-041's verb list (`POST /assets/{asset_id}/split`) / model it as a resource (`POST /asset-splits`) | **Add the verb.** It is the audited inverse of the existing merge; the resource form is the fallback if RFC-041 keeps the list closed |
| **D18** | Class and lens lists (§6.3.2) | fixed in code / tenant-editable | **Fixed in code**: 16 classes + `other`, grouped into 8 lenses. Tenants organise with groups and labels; editable classes would make cross-tenant docs, reports and lenses meaningless |
| **D19** | Per-type attribute storage (§6.3.3) | (a) schema-validated JSONB + generated partial expression indexes, extension tables only for 1:n data; (b) one extension table per type; (c) untyped JSONB (today) | **(a)**: typed facets without 37 tables; extension tables kept where data is not one row per asset (services, components, repositories) |
| **D21** | Default visibility of unconfirmed assets (I17) | show all / hide `needs_review` and `candidate` by default | **Hide by default**: the default OQL base is `attribution:confirmed,null` with a banner "N assets need review" linking to the RFC-036 review queue; dashboards and scheduled scans already follow the gate |
| **D20** | Default inventory landing view | All assets / External surface | **All assets** (core columns + type-aware cell), with External surface one tab away; the EASM workspace (`/attack-surface`) opens on External surface |

## 13. Sources

- Research in the workspace (2026-10-03):
  - `01-easm-best-practices`: lineage and graph-cut exclusions,
    confidence and hop distance, seed groups and cadence,
    observations and diffs;
  - R2 template-triggered scans, R5 asset policies;
  - `02-scan-orchestration-ha`: transactional outbox, `SKIP LOCKED`
    claims, at-least-once delivery;
  - `08-inventory-system-design`: per-source records → correlation →
    canonical rows; deterministic, windowed identity keys; single-flight
    correlation; zone boundaries; run-tag change detection with scoped
    cleanup; Fetch/Map/Load/ScopedCleanup connectors; identity fields;
    field/operator/value query grammar; attribution states;
  - `09-multi-type-inventory`: two-level class/type taxonomy, EASM as
    a subset of the shared model, one polymorphic table with per-type
    schemas, OCSF `resource_details` core, `jsonb_path_ops` and
    expression indexes, class tabs with per-tab columns, two-layer
    filters, an ownership state independent of type (OCSF, PostgreSQL
    docs);
  - dynamic groups as saved filters over the parent discovery, bulk
    label and status by filter, rules-based asynchronous auto-labels,
    asynchronous headless-Chrome screenshots;
  - exposure graph, aggregation layer.
- Fingerprint data:
  - `projectdiscovery/wappalyzergo` (MIT), data from
    `enthec/webappanalyzer` (GPL-3.0) and `HTTPArchive/wappalyzer`
    (GPL-3.0), licences checked via the GitHub API 2026-10-03.
- OWASP CSV Injection: <https://owasp.org/www-community/attacks/CSV_Injection>
- OWASP Open Asset Model (RFC-036 [100]) for vocabulary alignment.
- Perceptual hashing: pHash (DCT) and dHash; multi-index hashing for
  Hamming search (Norouzi, Punjani, Fleet, "Fast Search in Hamming Space
  with Multi-Index Hashing", CVPR 2012).
- RFC 9457 (Problem Details), RFC 9110 §9.2.1 (safe methods), via RFC-041.
