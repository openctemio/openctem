# Asset inventory v2

This page is the working reference for how the inventory is modelled,
queried, grouped, excluded and automated. The decisions and their reasons
are in [RFC-042](../rfcs/RFC-042-asset-inventory-v2.md).

- **Status: planned.** RFC-042 was accepted on 2026-10-03, with owner
  decisions D1–D21 as recommended. Nothing on this page is built yet
  unless a section says so. P0 ships as the seven slices in RFC-042 §9.1.
- Update each section from "planned" to "shipped" in the PR that lands
  it.
- The UI design is in `web/docs/ui/inventory-integrations-2026-10.md`.

## The model in five lines

1. An **asset** has identity ([RFC-028](../rfcs/RFC-028-asset-identity-model.md)),
   owner, criticality, attribution ([RFC-036](../rfcs/RFC-036-easm.md)) and
   labels.
2. A **service** is one `host:port/transport` row in `asset_services`.
   Its HTTP, TLS, network, technology, label and screenshot columns are
   typed. People browse services.
3. An **observation** is a facet value seen over a time span. A row is
   written only when the value changes (`inventory_observations`).
4. **OQL** is the single query language for lists, facets, group-by,
   saved filters, dynamic groups, policies, exports and scan selections.
5. The **target gate** (`scope.Gate`) decides whether anything may be
   probed. Every dispatch path calls it.

## Classes, the type registry and lenses

OpenCTEM has 37 asset types. Each type belongs to exactly one fixed
**class**, JupiterOne's `_class` above `_type`. Each class belongs to
exactly one **lens**, which is a UI tab. The source-native type
(`aws_instance`, `github_repo`) stays on the source record for
provenance.

| Lens | Classes (types) |
|---|---|
| External surface | `domain` (domain, subdomain), `ip_address`, `certificate`, `service` (service rows, generic service), `web_endpoint` (discovered_url) |
| Applications | `application` (application, website, web_application, api, mobile_app) |
| Cloud & infrastructure | `host` (host, compute, endpoint), `function` (serverless), `cloud_account` |
| Containers & Kubernetes | `container`, `cluster` (kubernetes*), `artifact_registry` (container_registry) |
| Code | `code_repo` (repository) |
| Identities | `identity` (identity, iam_user, iam_role, service_account) |
| Data | `data_store` (database, data_store, storage, s3_bucket) |
| Network | `network` (network, vpc, subnet, firewall, load_balancer) |
| (All assets only) | `other` (unclassified) |

OQL has `lens:`, `class:` and `type:` core fields.

**Stored types vs input names** ([RFC-042 §6.3.8](../rfcs/RFC-042-asset-inventory-v2.md#638-type-model-hardening-amendment-2026-10-03)).
Of the 38 names in the table, 17 are **core types** and are the only
values `assets.asset_type` may hold. The other 21 (`website`, `api`,
`compute`, `iam_user`, `s3_bucket`, `firewall` …) are **aliases**: input
names that every write path (REST, CSV and bulk import, importers,
ingest, connectors, seeds) resolves to (core type, sub_type). Feature
code keys on the class or on (type, sub_type), never on an alias.

- A **sub-type is a kind**, from a closed list per core type. A vendor is
  the `provider`, an engine or OS is an attribute. Legacy sub-type values
  are mapped on input (`postgresql` → `relational` + `engine`).
- REST and import reject an unknown sub-type; ingest keeps it in
  `properties.x_native_sub_type` and stores no sub-type.
- Behaviour is declared in the registry: `scannable_by` (the tool target
  types that can scan the type), `exposure_default`, and the relationship
  constraints resolved to (core type, sub_type).
- Type-aware features read the registry on the stored pair, never a type
  name: exposure inference (`exposure_default`), asset-group counters (by
  class), scan coverage, threat-model applicability (keyed by
  `(asset_type, sub_type)`, migration 000457), relationship constraints
  (enforced on human writes, after the tenant and data-scope checks),
  scanner compatibility (`scannable_by`), assignment-rule type conditions,
  and the web scope, relationship and create-finding matchers. A row still
  stored under an alias name reads as its alias's pair until the data
  normalisation (T3).
- Scanner compatibility is **enforcing** (O6): a scanner is handed only
  the asset-group members whose stored (type, sub_type) its target types
  can scan, at run dispatch and again at every workflow step's command
  (`internal/app/scan/type_gate.go`). A run or step with nothing left is
  refused (`NO_COMPATIBLE_TARGETS` / `INCOMPATIBLE_TARGETS`); assets whose
  compatibility cannot be decided are dispatched.
- An endpoint is a host (migration 000773): `endpoint` is an input alias
  of `(host, workstation)`, so a laptop seen by a network scan and by EDR
  is one host family for identity matching; 16 core types.
- One web sub-type (O3, migration 000685): a web application is stored as
  `(application, website)` and labelled "Web application";
  `web_application` is an input name only (`type_inputs`).
- Stored data is normalised (T3, migration 000684): every row holds a core
  type and a declared sub-type, enforced by `chk_assets_core_type`. Each
  move is ledgered and reversible, recorded as a `reclassified` history
  entry, and look-alike applications are queued for dedup review, never
  merged. Deploy it with an explicit migrate step (`air` does not migrate).
- Status: rules accepted 2026-10-03; implementation in the T1–T3 PRs of
  §6.3.8. This page moves the bullets to "shipped" as they land.

**The registry.** `api/configs/asset-types.yaml` is the single
definition. `make generate-asset-types` emits Go and TypeScript, and
`GET /api/v1/asset-types` serves the same data to the web. Per type it
declares:

- the class;
- the attribute schema;
- facets and group-by fields;
- the row and card renderer names;
- the detail sections;
- allowed relationships;
- identity keys in match order;
- the scanners that accept the type.

**Storage.** Per-type attributes live in `properties` JSONB, validated
against the schema. Every facet attribute gets a generated partial
expression index, and a `jsonb_path_ops` GIN index serves containment
queries. Core facets are real columns. Extension tables are used only for one-to-many data
(`asset_services`, `asset_components`, `asset_repositories`).

**Retired.** These are replaced by the registry or generated from it:

- `category.go`;
- `asset_type_categories`;
- `category-templates.tsx`;
- the per-type `config.tsx` pages.

**Lenses.** A lens is a registry preset: its classes or base query, its
row or card, and its default facets and group-by. The lenses are:

- All assets (core columns + a type-aware cell);
- External surface (rich service rows);
- Applications;
- Cloud & infrastructure;
- Containers & Kubernetes;
- Code;
- Identities;
- Data;
- Network.

The old `/assets/<type>` pages redirect to lens presets.

**The unified core** applies to every type: name, type, class, owner,
criticality and effective criticality, attribution state and confidence,
exposure, labels, first and last seen, sources, open findings and groups.

**Attack surface to code.**
`GET /api/v1/assets/{asset_id}/paths?to_class=code_repo` walks
traversable relationship types, for example

> domain → subdomain → IP → service → application → load balancer →
> workload → container ← repository (`deployed_to`)

with data scope applied at every hop.

## The property schema

An asset's free-form `properties` follow one schema per type
([RFC-042 §6.3.9](../rfcs/RFC-042-asset-inventory-v2.md#639-the-property-schema-amendment-2026-10-07)),
declared in `api/configs/asset-types.yaml`:

- `properties`: every key once, with `label`, `label_vi`, `format` (`ip`,
  `url`, `code`), `synonyms` and, when restricted, `classes`;
- each type's `attributes`, plus `common_properties` for every type.

| Concept | Canonical key | Folded synonyms |
|---|---|---|
| The asset's addresses | `ip_addresses` (list) | `ip`, `ips`, `ip_address` (string), `resolved_ip`, `resolved_ips`, `addresses` |
| Name servers | `nameservers` | `nameserver` |
| Technologies | `technologies` | `technology` |
| Certificate SANs | `sans` | `san` |

Writers fold synonyms with `asset.NormalizeProperties` (ingest, REST,
import). Readers use `asset.IPAddresses` / `asset.PropertyStrings`, which
also read a synonym an older row still holds; SQL builds its predicate from
`asset.AddressPropertyKeys`. A key restricted to classes (`port`, HTTP
status, banner, ...) is never stored on another class: ingest routes a port
on a domain, host or address to that asset's `host:port/proto` open-port
service (`exposes`), REST and import refuse it. A domain's addresses are
also `resolves_to` edges to IP assets (first seen `created_at`, last seen
`last_verified`).

The web Properties section renders from the generated schema: labels in
the viewer's language, addresses linked to their IP assets, unknown keys
under "Other".

## Three layers: source record, link, canonical row

| Layer | Asset | Service |
|---|---|---|
| Per-source record | `asset_sources` (`contributed_data`, run tag) | `service_sources` |
| Correlation link | `asset_sources.linked_by` / `linked_run_id` (view `asset_links`) + RFC-028 `asset_identifiers` | through the asset |
| Canonical row | `assets` | `asset_services` |

**At ingest.** Ingest upserts the source record and matches inline on
strong keys only (an RFC-028 strong identifier or an exact name).

**The correlation job.** It is single-flight per tenant and scan zone,
and runs after scan runs (5-minute debounce) and nightly. It:

1. proposes windowed hostname and IP matches to dedup review (the IP
   window defaults to 3 days);
2. recomputes preferred fields (RFC-003 source priority was withdrawn; the
   precedence rule is decided when this job is built);
3. writes the snapshot used by the rollups.

**The zone boundary.** Private addresses (RFC 1918, ULA, CGNAT) are keyed
by (zone, address), so two zones never merge `10.0.0.5`. Public addresses
and names correlate tenant-wide.

**Merge and split.** Merge is `ApproveAndMerge`. Split is
`POST /api/v1/assets/{asset_id}/split`. Both are audited.

**Gone.** "Gone" is decided only inside the targets, ports and zone a
completed run covered. A gone service becomes `closed` and a gone asset
`stale`; neither is ever deleted.

## Tables

| Table | Purpose | Phase |
|---|---|---|
| `asset_types.class`, `assets.asset_class`, `assets.asset_lens` | Class and lens from the registry, denormalised for facets | P0 |
| `asset_services` (evolved) | Service rows; typed HTTP/TLS/network columns; `legacy_asset_id`; `open_finding_count`, `max_open_severity` | P0 |
| `assets` (+ `dns_a`, `dns_aaaa`, `dns_cname`, `dns_resolved_at`, `apex_domain`, `system_labels`) | DNS belongs to the name | P0 |
| `findings.service_id` | Which service a finding is on ("Issues found") | P0 |
| `technologies`, `technology_categories` | Global catalog imported from webappanalyzer (GPL-3.0), pinned per release | P0 |
| `service_technologies` | Detected technology + version (`version_key int[]` for comparisons) per service | P0 |
| `labels`, `label_assignments` | Label definitions; provenance for system and policy labels. Custom labels stay in `tags` arrays | P0 |
| `saved_filters` | Named OQL queries, visibility private/tenant/roles | P0 |
| `inventory_facet_counts` | Per-tenant snapshot for unfiltered facets, with `computed_at` | P0 |
| `asset_groups` (+ `kind`, `subject`, `query`, `origin`, `cadence`, run fields, counts) | Static and dynamic groups | P0 |
| `asset_group_service_members` | Static groups of services | P0 |
| `asset_policies`, `asset_policy_runs`, `asset_policy_effects` | Policy engine | P1 |
| `inventory_change` | Transactional outbox of inventory changes (`origin`, `chain_depth`) | P1 |
| `inventory_observations` | Change-only facet history (shared with RFC-036 P4) | P1 |
| `inventory_daily_rollups` | Trends; 400 days daily, then monthly | P1 |
| `service_sources`; `asset_sources` (+ `tenant_id`, `last_seen_run_id`, `linked_by`, `linked_at`, `linked_run_id`); view `asset_links` | Per-source records and correlation links | P1 |
| `scope_exclusions` (+ `applies_to`, `pattern_kind`, `effect`, `exclusion_kind`) | One exclusion model | P1 |
| `service_screenshots`, `screenshot_phash_bands` | Re-encoded captures and similarity index | P2 |
| `discovery_edges` | Lineage for candidates, assets and services | P3 |
| `content_releases` | New nuclei templates per content version | P4 |

Every table that references `assets` must be added to
`api/internal/infra/postgres/asset_merge_plan.go`.
`api/tests/integration/asset_merge_coverage_test.go` fails otherwise.

## OQL cheat sheet

```
port:443,8443                 any of
-label:staging                NOT
host:*.staging.acme.com       wildcard (one or more labels)
ip:10.0.0.0/8                 CIDR containment
tech:jquery tech.version<3.5  technology and version compare
tls.expires<30d               relative time (from now)
first_seen>-7d                within the last 7 days
(title:*jenkins* OR tech:jenkins) is.public:true
title="Sign In"               exact, case-sensitive (":" is fuzzy)
tls.issuer:*                  field is non-empty
services:(port:22 AND banner:*OpenSSH_7*)   one service must match all
source:nessus port:3389       restrict to one source's records
```

- Juxtaposition means AND. `OR`, `NOT` and parentheses work as usual.
- Fields come only from the registry in `api/internal/app/oql`.
- Values are always bound parameters.
- The compiler always adds the tenant predicate and, for non-admin
  callers, the data-scope predicate.
- Limits: 2,000 characters, 64 clauses, depth 8.
- `POST /api/v1/oql/validate` returns the canonical form, an English
  explanation and any errors.

## Facets and group-by

- `GET /api/v1/services/facets?q=&fields=&size=` returns value counts per
  field.
  - With facet-menu queries, each field is counted without its own
    clause (multi-select).
  - Unfiltered requests read the snapshot and return `"source": "snapshot"`
    with `as_of`.
  - Filtered requests run live, per field, under a 1.5 s timeout.
  - A field that times out returns a bounded-sample count marked
    `"exact": false`.
- `GET /api/v1/services/groups?group_by=<field>&q=` returns groups with a
  count, the first `items_per_group` services, and a `query` string.
  - Paging inside a group: `GET /api/v1/services?q=<that query>`.
  - Export: `POST /api/v1/services/exports {q}`.
  - Scan: `POST /api/v1/scans/preview {selection: {q}}`.
- Supported `group_by` values: `tech`, `port`, `label`, `domain`, `host`,
  `ip`, `cname`, `status`, `title`, `server`.

## The target gate

```
allowed(t) = not archived
         AND attribution allows active checks (NULL = legacy confirmed)
         AND not excluded (name, aliases, resolved IPs, lineage ancestors)
         AND tier <= ceiling
         AND tool accepts the type
```

It runs at:

- scan trigger;
- RFC-030 claim;
- every pipeline hop;
- `POST /pipelines/runs` with targets;
- the scan-coverage dispatcher;
- quick scans;
- policy-triggered scans;
- validation re-checks.

It returns `allowed[]` and `skipped[{target, reason}]`.
`POST /api/v1/scans/preview` shows the same result before a scan is
created, and returns a `preview_token`. The token is valid for 15 minutes.
The gate runs again at dispatch whatever the preview said.

## Exclusions

| Pattern | Matches |
|---|---|
| `acme.com` | that name only |
| `*.acme.com` | `acme.com` and every name below it (RFC-054 §4.1); add an exclusion of exactly `acme.com` for the subdomains only |
| `test.*.acme.com` | exactly one label in the middle |
| `10.0.0.0/8`, `10.0.0.1-10.0.0.9` | addresses |

- **Approval.** The approval workflow from migration 267 is unchanged.
  Approved, active, unexpired rows count; a requester cannot approve their
  own exclusion.
- **Discovery.** Collectors and ingest do not create anything from a
  discovery source that matches. A tenant-targeted name that matches is
  created **archived** with `archived_reason = excluded:<id>`.
- **Dispatch.** The gate.
- **Graph cut.** When an exclusion is approved, descendants in
  `discovery_edges` whose every path to a root passes through an excluded
  node are archived with `excluded_ancestor:<asset_id>`.
- **Reversal.** Removing, rejecting or expiring an exclusion un-archives
  exactly the rows archived because of it.
- **Never delete.** No exclusion path deletes an asset.

## Policies

**Lifecycle:**

1. Draft. A new policy is disabled.
2. `POST /asset-policies/{asset_policy_id}/preview` returns the count,
   samples, per-action effects and cap warnings.
3. `/enable` is accepted only with a preview that matches the current
   definition and is less than 24 hours old.
4. Runs happen on triggers (`discover`, `change` with facets,
   `schedule`) or manually through `/run`.
5. Any edit disables the policy again.

**Actions:** `add_label`, `remove_label`, `notify`, `archive`,
`mark_out_of_scope` (a pending exclusion, through approval),
`set_criticality`, `set_owner`, `trigger_scan` (through the gate, the
budget and a second approver). There is no delete.

**Safety:**

- **Self-origin skip.** A policy never fires on its own changes
  (`origin = policy:<id>`).
- **Depth.** Chain depth is limited to 3.
- **Caps.** Per-run caps: 1,000 subjects; archive min(100, 5 %).
  Exceeding a cap pauses the policy as `paused_needs_confirmation`.
- **Breaker.** Three capped runs in a row set `disabled_breaker`.
- **Tenant ceilings.** At most 50 enabled policies and 10,000 effects per
  hour.
- **Audit.** Every effect is recorded in `asset_policy_effects`. One
  audit-log entry per run.
- **Restore.** `POST /assets/bulk/reactivate {selection: {policy_run_id}}`
  restores a run's archives.

## Screenshots

**Capture on the sensor** (`octm-shot`):

- Chromium sandbox on, non-root, 512 MB, 20 s;
- the host is pinned to the scanned IP;
- private, metadata and non-HTTP requests are blocked unless the zone is
  internal and the address is in scope;
- no downloads, service workers or persistent profile;
- egress through the zone's RFC-034 profile.

**Upload** to `POST /api/v2/sensor/screenshots`.

**On the API:**

- decode the PNG and re-encode to WebP (400 KB cap) plus a 320-px
  thumbnail (40 KB cap);
- recompute the pHash;
- store at `screenshots/<tenant>/<sha256>.webp` through `FileStorage`;
- never store SVG or the original bytes.

**Serving:**

- path: `GET /api/v1/services/{service_id}/screenshots/{screenshot_id}/image`;
- requires `assets:read` and data scope;
- headers: `image/webp`, `nosniff`, `CSP: default-src 'none'; sandbox`,
  `CORP: same-origin`;
- no public or presigned URLs.

**Clusters:** Hamming distance ≤ 3 is matched immediately through four
16-bit bands; distance 4–6 is matched by the nightly reconcile.

**Retention:** 30 days, but the latest capture per live service is always
kept. The default quota is 5 GB per tenant; when it is reached, capture
pauses with a visible warning.

## Change kinds and alerts

| Kind | Source facet |
|---|---|
| `asset_created`, `service_created` | insert |
| `service_closed` | ports, after two consecutive misses |
| `cert_changed`, `cert_expiring` (30/14/7/1 d) | tls |
| `tech_added`, `tech_removed`, `tech_version_changed` | tech |
| `title_changed`, `status_changed`, `server_changed` | http |
| `dns_changed` | dns |
| `screenshot_changed` | screenshot (pHash distance > 10) |

- Alerts are per-tenant digests through the outbox.
- A notification integration can filter them with an OQL query.
- The in-memory `new_asset` throttle in `assetdiscovery.Notifier` is
  replaced by an outbox digest row, so several API replicas no longer
  send duplicate digests.

## Honest numbers

Every metric in `/inventory/trends`, `/inventory/distributions`, the facet
responses and `/inventory/content-checks` carries one of:

- `status: ok`;
- `status: partial`, which lists the missing days;
- `status: insufficient_data`, with a `reason`.

Counts carry `exact: false` when they are a lower bound. Lists cap the
total at "10,000+". Trends are never back-filled from before the first
observation, and days are never interpolated.

## Performance targets

See [RFC-042 §7](../rfcs/RFC-042-asset-inventory-v2.md#7-performance-targets).
In short, at 100k services per tenant:

| Operation | p95 target |
|---|---|
| List | ≤ 300 ms |
| Filtered facets | ≤ 600 ms |
| Group-by page | ≤ 600 ms |
| Dynamic group resolution at dispatch, 10k members | ≤ 2 s |

The `api/tests/perf/inventory` fixtures and the `EXPLAIN` guard tests
hold these targets.

## Related

- [RFC-042](../rfcs/RFC-042-asset-inventory-v2.md): the design and the
  owner decisions.
- [RFC-036](../rfcs/RFC-036-easm.md) and [easm.md](easm.md): seeds,
  attribution, candidates and the review queue.
- [change-detection.md](change-detection.md): state history and the
  existing triggers.
- [asset-identity-resolution.md](asset-identity-resolution.md) and
  [RFC-028](../rfcs/RFC-028-asset-identity-model.md): identity and merge.
- [scan-orchestration.md](scan-orchestration.md) and
  [RFC-030](../rfcs/RFC-030-scan-work-distribution.md): dispatch and
  claim-time chunks.
- [notification-system.md](notification-system.md): the outbox and its
  channels.
