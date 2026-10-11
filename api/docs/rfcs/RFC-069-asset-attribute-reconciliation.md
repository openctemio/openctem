# RFC-069: Asset attribute reconciliation

| | |
|---|---|
| Status | Accepted (2026-10-09, delegated; D1–D3 adopted as recommended, §10). P0, §11 (ordering, change timeline) and §12 (precedence per class) delivered; §13 (per-source sets) in implementation |
| Scope | api (`pkg/domain/asset`, `internal/app/asset`, `internal/app/ingest`, the asset repository, migration `asset_attribute_sources`), web (asset "Where values come from" section, Settings › Asset sources) |
| Architecture | [asset-attribute-reconciliation.md](../architecture/asset-attribute-reconciliation.md) |
| Related | RFC-005 (asynchronous ingest), RFC-040 (sensor result binding), RFC-042 (inventory v2), RFC-043 (identity), RFC-066 (software inventory), [asset-source-priority.md](../architecture/asset-source-priority.md) (RFC-003, withdrawn), [data-sources.md](../architecture/data-sources.md) |

## 1. Summary

An asset is reported by many sources: sensor scans, file imports, integrations
and people. When they disagree, the asset must show the value of the source
that is most trusted for that attribute and, among equally trusted sources,
the one that saw it most recently. A late report must never undo a newer one,
a sensor must not set what it is not trusted for, and a person's edit must
hold until the person releases it.

The platform records, for each tracked attribute of each asset, every
source's latest value with when that source saw it. A resolver picks the
winner by precedence, then recency, then confidence, and the winner is
written to the asset's existing column. Readers do not change.

## 2. Current state (develop b32245098)

- Ingest merges an existing asset in Go and again in the upsert's `ON
  CONFLICT` clause (`internal/infra/postgres/asset_repository.go`
  `assetUpsertConflictSQL`). The rule differs per column, by accident:
  - `owner_ref`, `data_classification`, `sub_type`, CIA impact: fill a gap
    only. The first writer wins forever; an authoritative source can never
    correct a value an early scan or import filled in.
  - `exposure`: taken only while `unknown`.
  - `criticality`: set when ingest creates the asset, never updated.
  - `properties`: deep merge; "newer wins" compares `last_seen`, which is
    the arrival time (`Asset.MarkSeen` uses `now()`), so the newest
    **arrival** wins, not the newest observation.
  - `tags`, arrays in `properties`: union forever.
- The report's observation time (`metadata.timestamp`, required) is never
  used to order writes. Reports are queued (RFC-005); delayed, retried and
  quarantined-then-accepted reports arrive out of order.
- A sensor may fill `owner_ref` and `data_classification`; `owner_ref` feeds
  owner resolution and finding assignment.
- A person's edit holds only because ingest happens not to write those
  columns.
- Per-element data already has its own sources: open ports are `open_port`
  assets closed by the same kind of scan (`ingest/ports.go`), software is
  `asset_software` with source and confidence (RFC-066), identifiers keep a
  source and first/last seen.
- RFC-003 (per-organization source priority, `data_sources`,
  `asset_sources`) was never wired and was removed in 2026-10.

## 3. Goals and non-goals

Goals (P0):

- G1. Per-attribute provenance: each source's value, when the source saw it
  (`observed_at`), when the platform recorded it (`ingested_at`) and how
  confident it is.
- G2. One resolution rule: a person's lock, then the organization's
  precedence for the attribute, then the most recent observation, then
  confidence.
- G3. Out-of-order safe: a source's older observation never replaces its
  newer one.
- G4. Staleness: a source that has not reported within its kind's TTL stops
  counting; staleness never clears a value.
- G5. Disagreement is visible ("sources disagree"), not silent flapping.
- G6. A source is trusted per attribute; a sensor never decides an attribute
  the organization does not trust scanners for.
- G7. "Why this value" on the asset page; locks set and released there.

Non-goals (P0): technical scalars in `properties` (OS, hostname, region),
IP-address sets, tags, description and name; decommission by a connector
(no connector exists yet); per-source (rather than per-kind) precedence; an
observation history.

## 4. Options considered

| | A. Newest observation wins (per asset) | **B. Per-attribute precedence + recency** | C. Observation log, resolve on read |
|---|---|---|---|
| Out-of-order safe | yes | yes | yes |
| Trust per attribute | no: a scanner overwrites owner and criticality | yes | yes |
| Flapping between sources | yes | no (rank first) | depends |
| A person's edit | overwritten | lock | lock |
| "Why this value" | no | yes | yes |
| Storage | none | assets × tracked attributes × sources (small) | grows with every scan |
| Readers | unchanged | unchanged (resolved value in the column) | every reader changes |

B is chosen: it meets the goals with one table and no reader change. A
makes trust worse; C is the general model but costs every reader and grows
without bound.

## 5. Model

### 5.1 Source kinds

Closed list, decided by the platform from how the data arrived, never taken
from the report:

| Kind | Route |
|---|---|
| `manual` | a person: asset create and edit, the owner removal, the lock endpoint. Always a **lock** |
| `integration` | a connector the organization configured (DefectDojo sync today; cloud and inventory connectors when built) |
| `import` | a file a person uploaded (finding import, CTIS / SARIF upload) |
| `scan` | every sensor report (command-bound, unsolicited, CI run), platform scanners, and any server-side ingest that does not say otherwise, including a quarantined sensor report a person accepted |
| `feed` | a subscribed passive or published feed applied by a server-side importer (program feed, passive DNS); added in §12 |

Only a trusted binding (a server-side ingest) may name its kind
(`ingest.Options.SourceKind`); every sensor binding is `scan`. The source
name (tool, importer, integration, user id) is informational.

### 5.2 Tracked attributes (P0)

`criticality`, `owner_ref`, `exposure`, `data_classification`: the business
columns that drive priority, ownership and assignment, and that were
first-writer-wins. The table is keyed by attribute name, so another
attribute is a list entry plus its column mapping, not a schema change.

### 5.3 Table

```
asset_attribute_sources
  tenant_id, asset_id        -- FK (tenant_id, asset_id) -> assets, cascade
  attribute                  -- criticality | owner_ref | exposure | data_classification
  source_kind                -- manual | integration | import | scan
  source_name                -- tool, importer, integration or user id (<= 100)
  value                      -- normalised per attribute (<= 500)
  observed_at                -- when the source saw it (report timestamp, never in the future)
  ingested_at                -- when the platform recorded it
  confidence smallint 0-100  -- tie-break only
  PK (tenant_id, asset_id, attribute, source_kind, source_name)
```

A row is replaced only by an observation of the same source with
`observed_at` at or after the stored one. A manual row replaces the
attribute's other manual rows (one lock per attribute).

### 5.4 Resolution

For one attribute of one asset:

1. A `manual` row is a lock and wins (never stale).
2. A kind not in the organization's precedence list for the attribute is
   **untrusted** and ignored.
3. A row older than its kind's TTL is **stale** and ignored.
4. The rest rank by precedence, then `observed_at` (newest first), then
   confidence, then `ingested_at`, then name (deterministic).
5. No candidate: the asset keeps its current value.
6. The most trusted fresh rank holds different values: **conflict**. The
   value the asset already shows then keeps winning while a source of that
   rank still reports it: equal sources disagreeing are shown, not flapped
   between (§11). Different ranks disagreeing is precedence, not a conflict.

Defaults (`asset.DefaultReconciliationPolicy`):

| Attribute | Precedence after manual |
|---|---|
| criticality, owner_ref, data_classification | integration, import (scanners not trusted) |
| exposure | scan, integration, import (a scan that reached the asset beats an inventory's claim) |

TTL: integration 30 days, import 90 days, scan 30 days, manual never. An
organization may reorder or drop kinds per attribute and change TTLs
(`tenants.settings.asset_reconciliation`, `GET/PUT
/api/v1/organization/settings/asset-reconciliation`, owner or admin). Manual
is always first and cannot be listed.

### 5.5 When it runs

One code path (`AssetService.applyAttributes` → `AttributeSourceRepository.Apply`)
locks the touched asset rows in id order, records the observations, releases
locks, resolves, writes changed columns, and returns the changes, in one
transaction. Then each change is recorded in `asset_state_history`
(`criticality_changed`, `owner_changed`, `exposure_changed`,
`classification_changed`) with the winning source in the reason, the asset
is re-scored when criticality or exposure changed, and the owner derived
from `owner_ref` is synced.

- **Ingest:** after the asset upsert and before findings are prioritised,
  the report's stated values (CTIS `criticality`, owner from
  `compliance.regulatory_owner` / repository owner / `properties.owner`,
  `is_internet_accessible` or `properties.exposure`,
  `compliance.data_classification`) are recorded for the assets the report
  may change (RFC-040 §5.3 reach), with `observed_at` = the report
  timestamp clamped to now. An asset a report creates does not take the
  `owner_ref` or `data_classification` its source is untrusted for. Ingest
  no longer fills `owner_ref` or `data_classification` on existing assets
  itself.
- **People:** a create records the values the person chose as locks (no
  behaviour change: no source changed them before); an edit locks the
  tracked values the person changed; removing the owner derived from
  `owner_ref` locks an empty `owner_ref`; `PUT
  /assets/{id}/attribute-sources/{attribute}/lock` sets and locks;
  `DELETE …/lock` releases (the attribute is decided by its sources again).

### 5.6 Out of order beyond the four attributes

P0 also makes the rest of ingest observation-ordered (separate change):
`last_seen` and the property-merge freshness rule use the report's
observation time; a re-observed stale asset is saved active (the upsert
dropped the status `MarkSeen` set); the port closer only closes ports last
seen before the closing report's observation time.

### 5.7 Sets

IP addresses, technologies and open ports are reconciled per source and
per element (§13). Software keeps its own per-element mechanism
(`asset_software`, RFC-066 superseding and `not_observed`).

### 5.8 Existence

Any source that reports an asset keeps it active (`last_seen`); the lifecycle
worker demotes it when no source has reported it within the threshold.
Decommission by an authoritative source (a cloud connector saying the
instance is terminated) is P1, with the first connector.

## 6. API

| Route | Gate | |
|---|---|---|
| `GET /api/v1/assets/{id}/attribute-sources` | `assets:read` + data scope | per attribute: value, locked, conflict, decided_by, every source with status `winner` / `outranked` / `stale` / `untrusted` |
| `PUT /api/v1/assets/{id}/attribute-sources/{attribute}/lock` `{value}` | `assets:write` + data scope | set and lock; audited (`asset.updated`) |
| `DELETE /api/v1/assets/{id}/attribute-sources/{attribute}/lock` | `assets:write` + data scope | release; audited |
| `GET/PUT /api/v1/organization/settings/asset-reconciliation` | owner/admin | precedence and TTL; audited (`tenant.asset_source_updated`) |

## 7. Threat model

| Threat | Control | Test |
|---|---|---|
| A compromised sensor sets the owner (finding assignment) or classification of an asset | kind decided by the binding (every sensor report is `scan`); scanners untrusted for both by default; a created asset drops untrusted claims; existing assets are no longer gap-filled by ingest | `TestAttributeReconciliation_ScanDecidesExposureButNotOwner`, `_PrecedenceRecencyAndOrder` (scan claims ignored), `TestResultBinding_BoundResultsStillApply` |
| A sensor claims to be an import or integration | `Options.SourceKind` is honoured only for a trusted binding; a quarantined report a person accepts stays `scan` | `reportSource` |
| A sensor writes facts about assets outside its reach | observations only for assets the report may change (`alterScope.allowedAsset`, RFC-040 §5.3 / #1646) | binding tests |
| A replayed or delayed report undoes newer data | per-source `observed_at` guard; future timestamps clamped to now | `_PrecedenceRecencyAndOrder` |
| A stale source keeps winning | per-kind TTL | domain table tests |
| Cross-tenant write or read | observations dropped unless the asset is the tenant's (rows locked `WHERE tenant_id`); composite FK; routes behind the asset data-scope guard and `GetAssetInCallerScope` (out of scope = 404) | `_TenantIsolation`, `TestAttributeSources_*` |
| Unauthorised lock | `assets:write` + data scope; settings owner/admin | `TestAttributeSources_ReadOnlyCannotLock`, `TestAssetReconciliationSettings_*` |
| Invalid values reach a column | values normalised per attribute before storage and again in the repository | domain and route tests |
| Silent change | every resolved change in `asset_state_history` with its source; locks and settings audited | integration test |
| Personal data | `owner_ref` may be an email; rows go with the asset (cascade, merge plan) and the tenant | merge coverage test |

## 8. Rollout

Migration `001652_asset_attribute_sources` creates the table and turns the
values people set into locks: on assets a person created (no
`discovery_source`, or `manual`) the current criticality, owner_ref,
exposure and data classification; on any asset, an attribute with a manual
change in `asset_state_history`. Values ingest filled in get no row and are
kept until a trusted source reports the attribute. Production restore
(2026-10-09): 184 assets, 155 lock rows on 79 assets. Down drops the table;
the resolved values stay on the assets.

Behaviour changes: a sensor no longer fills `owner_ref` or
`data_classification`; an import or integration now updates criticality,
owner and classification of assets nobody locked.

## 9. Phases

- **P0:** model, resolver, migration, ingest capture, locks, API, settings,
  web section and settings page; observation-ordered `last_seen`, property
  merge and port closing; stale→active persistence.
- **P1:** per-source sets (IP addresses, technologies); technical scalars
  (OS, hostname, region); decommission by an authoritative connector;
  conflict filter in the inventory list; bulk re-resolution after a
  settings change (today values move when sources next report).

## 10. Decisions

- D1: scanners are not trusted for criticality, owner or data
  classification by default. Adopted; an organization can trust them.
- D2: values people set before the upgrade become locks. Adopted.
- D3: TTLs scan 30 d, integration 30 d, import 90 d. Adopted.

## 11. Observation ordering and the change timeline (owner requirements, 2026-10-10)

### 11.1 Ordering

- Every observation carries source kind and name, `source_run` (scan task,
  CI run, import or feed sequence), `observed_at`, `received_at`
  (`ingested_at`) and confidence.
- Per source, an observation is applied only when it was made strictly
  after the source's stored one (`asset.ClassifyObservation`); older ones
  (`out_of_order`) and same-time ones (`replay`) are ignored and counted
  (`openctem_asset_attribute_observations_total{verdict}`).
- A re-sighting of the same value refreshes `observed_at` at most once an
  hour (`refresh`); within the hour nothing is written (`resighted`).
- A sensor report's observation time is its timestamp clamped to
  [the bound command's dispatch time (acknowledgement, else creation),
  arrival], once for the whole report.
- The resolver marks the deciding row (`winner`), so a change of the deciding
  source is known even when the value stays.

### 11.2 Timeline

`asset_change_events` (monthly partitions on `at`, default partition,
indexes `(tenant_id, asset_id, at desc, id desc)` and `(tenant_id, at desc,
id desc)`): one event per change of the shown value or of the deciding
source, written in the reconciliation transaction. Fields: tenant, asset,
`at`, attribute, old → new (`added`/`removed` for set attributes), source
kind/name/run, actor (lock, release), reason (`newer_observation`,
`manual_lock`, `lock_released`, `ttl_expiry`, `policy_change`,
`source_removed`), `flap_count`.

- No event for a re-sighting.
- A value flipping back and forth between sources within an hour is one
  event with a count (`ChangeEvent.Coalesces`); a person's lock or release,
  a TTL expiry and a policy change are always their own events.
- Partitions: the server runs no DDL (least-privilege role), so the
  migration creates last month through the next two years and a later
  migration extends them; anything outside lands in the default partition.
- Retention: `ASSET_CHANGE_RETENTION_DAYS` (default 400, minimum 30); the
  `asset-change-timeline` controller deletes expired events in batches, and
  once a day re-resolves every asset with a recorded source so a value whose
  deciding source passed its TTL moves on (`ttl_expiry`).
- Events cascade with the asset and the tenant (organization deletion erases
  them) and move with the asset in a merge. They hold only values the asset
  itself holds.

API: `GET /api/v1/assets/{id}/changes` (asset timeline) and `GET
/api/v1/assets/changes` (organization feed, data-scope filtered; filters
attribute, source kind, source name, tag), both `assets:read`, keyset
pagination (`cursor`, `limit` ≤ 200).

### 11.3 Threat model additions

| Threat | Control | Test |
|---|---|---|
| A sensor future-dates its report to win, or back-dates it before the job existed | timestamp clamped to [dispatch, arrival] for every consumer | `TestClampReportTimestamp`, `TestAssetTimeline_SensorClockIsClamped` |
| A replayed or reordered report rewrites history | strictly-newer rule per source; replay and out-of-order counted, never applied | `TestClassifyObservation`, `TestAssetTimeline_EventOnlyWhenTheValueChanges` |
| Two equal sources disagreeing make the value (and the timeline) flap | incumbent kept on an equal-rank conflict; reversals within an hour folded | `TestResolve` (equal rank), `TestChangeEventCoalesces`, `TestAssetTimeline_FlappingFoldsIntoOneEvent` |
| Write amplification from frequent re-sightings | no event; `observed_at` refreshed at most hourly | `TestAssetTimeline_EventOnlyWhenTheValueChanges` |
| Reading another tenant's or an out-of-scope asset's history | every query `WHERE tenant_id`; asset timeline behind `GetAssetInCallerScope` (404); feed narrowed to `user_accessible_assets` | `TestAssetChanges_*`, `TestAssetTimeline_ListIsTenantAndScopeIsolated` |
| History outliving erasure | FK cascade from assets (and so tenants); batched retention delete | `TestAssetTimeline_ListIsTenantAndScopeIsolated`, `TestAssetTimeline_PartitionsAndRetention` |

### 11.4 Status (see §12 for precedence)

Delivered: ordering, clock clamp, `source_run`, winner flag, equal-rank
conflicts, timeline table, API, controller (#1688). Next: the web Timeline
tab and the organization feed; per-source set attributes (§13); feed
bundle sequence and expiry checks for programfeed sources.

## 12. Precedence per attribute class (owner requirements, 2026-10-10)

Replaces the per-attribute kind lists of §5.4 (settings saved in the old
shape are dropped and the defaults apply; the feature was one day old).

- **Classes:** `identity`, `network` (exposure), `software`, `ownership`
  (criticality, owner_ref, data_classification), `cloud_tags`, `lifecycle`.
  Classes without reconciled attributes yet can be ranked already.
- **Rules:** each class has a ranked list or inherits the organization's
  default list. A rule names a kind or one source (`scan:nmap`), with its
  TTL and a trust flag. An observation takes the rank of the rule naming its
  source, else of its kind's rule; none or untrusted: it does not decide.
  Equal rank = same rule (§5.4 step 6 conflicts).
- **Kinds:** `feed` added for passive and published feeds (migration
  `asset_source_kind_feed`), named only by a trusted server-side ingest.
- **Defaults:** default list integration, scan, import, feed; ownership
  integration, import (scan, feed untrusted: D1 kept); network scan,
  integration, import, feed; TTL 30 d, import 90 d.
- **Saving** (owner/admin): a change that demotes a connector (an
  integration rule loses trust or its row, or a source ranks above it that
  did not) needs step-up re-authentication (`RecentAuthGate`, 403
  `STEP_UP_REQUIRED`); audited with `demotes_connector`. The organization's
  assets are then re-resolved in the background in batches; only changed
  values get a timeline event (`policy_change`). The daily sweep catches up
  if the process stops.
- **Preview:** `POST …/asset-reconciliation/preview` resolves the posted
  policy against one asset or up to 5000 assets with sources, read only:
  changed assets and values, conflicts, 25 samples.
- **Sources seen:** `GET` lists the sources that reported the
  organization's assets (kind, name, last seen, assets) for the settings
  rows.

| Threat | Control | Test |
|---|---|---|
| A member reorders sources to change owners or criticality | owner/admin only (`RequireAdmin`) | `TestAssetReconciliationSettings_RefusesInvalidAndNonAdmin` |
| A hijacked admin session quietly demotes the connector of record | step-up re-authentication for any demotion | `TestDemotesAuthoritative`, `TestAssetReconciliationSettings_DemotingAConnectorNeedsStepUp` |
| Preview or re-resolution crosses tenants | every read `WHERE tenant_id`; asset preview of another tenant's asset is 404 | `TestAssetReconciliationSettings_PreviewAndBackgroundReResolve` |
| A feed claims ownership data | feeds untrusted for ownership by default | `TestReconciliationPolicy_ClassesInheritTheDefault`, `TestAssetTimeline_FeedSourceKind` |
| Oversized policy | 50 rules per list, 64 KiB body, names ≤ 100 | `TestPolicyFromSettings` |

## 13. Per-source set attributes (owner requirements, 2026-10-10)

An asset's IP addresses, technologies and open ports are sets several
sources contribute to. A source that does not report an element has not
said it is gone: a partial scan must never delete what it did not look at.

### 13.1 Model

`asset_attribute_set_elements` (migration `asset_attribute_set_elements`):
one row per tenant, asset, attribute, source (kind, name) and element, with
`first_seen`, `last_seen` (observation time), `removed_at`, the
`coverage_key` of the observation that last saw it and `source_run`.
Composite FK to the asset (cascade, merge plan moves it).

| Attribute | Element | Shown as | Class (§12 rules: trust, TTL) |
|---|---|---|---|
| `ip_addresses` | canonical address | `properties.ip_addresses` | identity |
| `technologies` | `Name:version` as reported | `properties.technologies` | software |
| `open_ports` | `443/tcp` on an IP address asset | the address's `open_port` assets active / inactive | network |

### 13.2 Coverage

Each observation states what it looked at:

| Mode | Covers | Used by |
|---|---|---|
| `full` | every element of the source | DNS resolvers (dnsx, massdns, puredns, shuffledns) for IP addresses; fingerprinting probes (httpx, wappalyzer, webanalyze, whatweb) for technologies |
| `ranges` | TCP ports in the scanned ranges, plus elements seen under the same key | a port scan with an explicit list (`ports: 80,443,8000-8100`) or `full` |
| `keyed` | elements the same source last saw under the same key | a port scan with `top_ports`, `top-N` or no setting (`ports:top-100`, `ports:default`): it cannot name its ports, so it removes only what an earlier scan with the same setting found |
| `sightings` | nothing (TTL only) | every other report: imports, integrations, feeds, a web probe reporting the one address it connected to, a truncated list |

The coverage comes from the bound command's port settings (`config.ports`,
`config.top_ports`) and the report's tool, never from the report body.

### 13.3 Rules

- Per element and source, only an observation strictly newer than the
  record counts; an element removed at T is not revived by an observation
  before T (late and replayed reports change nothing).
- An element leaves a source's contribution (`removed_at`) only when the
  same source observes a coverage that includes it without it.
- A re-sighting refreshes `last_seen` at most hourly; nothing else is
  written and no event is recorded.
- The asset shows the union of the elements a trusted source still reports
  and saw within its TTL (§12 class rules), plus elements no source has a
  record of (values from before this change or other writers), which a
  trusted `full` or `ranges` observation that names them and leaves them out
  removes; a `keyed` one never does.
- Ingest no longer overwrites (`ip_addresses`) or unions forever
  (`technologies`) these properties on existing assets; it no longer closes
  ports by "the same kind of scan". A port closes when its set loses it:
  status `inactive`, `disappeared` history, `port_open`/`service_detected`
  exposures resolved; it reopens when a source reports it again.
- Timeline: one `asset_change_events` row per changed set with `added` /
  `removed` (≤ 200 each), source kind, name and run, reason
  `newer_observation`; the daily sweep and a policy change re-resolve sets
  too (`ttl_expiry`, `policy_change`). A change that exactly undoes the
  previous one within an hour folds into it (`flap_count`, latest
  direction).
- Retention: element rows removed or last seen before the timeline
  retention are deleted with the events.

### 13.4 Threat model

| Threat | Control | Test |
|---|---|---|
| A partial scan (or a sensor told to scan little) erases ports or addresses | removal only within the same source's coverage; keyed coverage never removes untracked values | `TestPortScanCoverage`, `TestPlanSetObservation`, `TestAssetSets_PortCoverage` |
| A sensor claims full coverage to wipe a set | coverage from the bound command's settings and the tool, every sensor report is `scan`; an untrusted source removes nothing from the shown set | `TestAssetSets_PortCoverage` |
| One source removes what another still reports | per-source records; union of trusted sources | `TestResolveSet`, `TestAssetSets_PortCoverage` |
| A delayed or replayed report revives or removes elements | strictly-newer per element, `removed_at` ordering | `TestPlanSetObservation`, `TestAssetSets_IPAddresses` |
| Flapping floods the timeline | exact reversal within an hour folds | `TestChangeEventCoalesces`, `TestAssetSets_IPAddresses` |
| Write amplification | re-sighting writes nothing within the hour; ≤ 1000 elements per observation (more: sightings) | `TestAssetSets_IPAddresses` |
| Cross-tenant write or read | asset rows locked `WHERE tenant_id`, observations of other tenants' assets dropped, open_port assets read and changed `WHERE tenant_id`; composite FK | `TestAssetSets_TenantIsolation` |

### 13.5 Not covered

Software links keep RFC-066's mechanism. Program targets and cloud tags have
no set attribute on assets yet; they join this table when they get one.
Manual locks on sets are not offered.

