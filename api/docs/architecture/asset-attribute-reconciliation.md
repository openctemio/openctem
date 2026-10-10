# Asset attribute reconciliation

> **Last updated**: 2026-10-09 · Design: [RFC-069](../rfcs/RFC-069-asset-attribute-reconciliation.md)

An asset hears from many sources: sensor scans, file imports, integrations
and people. For the attributes below the platform keeps every source's
latest value and shows the one the organization trusts most, most recently
seen. A person's change is a lock.

## Tracked attributes

| Attribute | Column | Class | Default precedence (after a person's lock) |
|---|---|---|---|
| `criticality` | `assets.criticality` | ownership | integration, import |
| `owner_ref` | `assets.owner_ref` | ownership | integration, import |
| `data_classification` | `assets.data_classification` | ownership | integration, import |
| `exposure` | `assets.exposure` | network | scan, integration, import, feed |

A source without a trusted rule is **untrusted** for that class: by default
a scanner or feed never decides criticality, owner or classification.
Default TTLs: 30 days, import 90 days, a lock never (see Precedence).

## Source kind

Decided by the route the data came through, never by the report:

| Route | Kind |
|---|---|
| asset create / edit, owner removal, lock endpoint | `manual` (a lock) |
| DefectDojo sync (future cloud / inventory connectors) | `integration` |
| finding import (a person's file) | `import` |
| every sensor report, CI run, platform scanner, accepted quarantined report, any other server-side ingest | `scan` |
| a subscribed feed applied by a server-side importer (program feed, passive data) | `feed` |

Code: `ingest.reportSource` (`internal/app/ingest/attributes.go`); only a
trusted binding may set `ingest.Options.SourceKind`.

## Storage

`asset_attribute_sources`: one row per (asset, attribute, source kind, source
name) with `value`, `observed_at` (when the source saw it), `ingested_at`
(received), `confidence`, `source_run` (scan task, CI run, import or feed
sequence) and `winner` (this row decides the shown value). Rows cascade with
the asset and move with it in an asset merge (`asset_merge_plan.go`).

`asset.ClassifyObservation` decides what an incoming observation does to its
source's row:

| Verdict | When | Write |
|---|---|---|
| `new` | the source had no row | insert |
| `changed` | strictly newer, different value | replace |
| `refresh` | strictly newer, same value, row at least 1 h old | `observed_at` only |
| `resighted` | strictly newer, same value, row refreshed within the hour | nothing |
| `out_of_order` | older than the row | ignored |
| `replay` | same `observed_at` as the row | ignored |

Counts go to `openctem_asset_attribute_observations_total{verdict}`.

Observation time of a sensor report: the report timestamp clamped to
[the bound command's dispatch time, arrival] (`clampReportTimestamp`), once,
before every consumer (reconciliation, `last_seen`, property merge, port
closing), so a skewed or hostile clock can neither future-date data to win
nor back-date it before the job existed.

`assets` keeps the resolved value: every reader (lists, priority, risk
score, owner resolution) is unchanged.

## Resolution

`asset.Resolve` (`pkg/domain/asset/attribute_source.go`):

1. a lock wins;
2. untrusted kinds are ignored;
3. rows older than their kind's TTL are ignored (stale);
4. rank: precedence, then newest `observed_at`, then confidence, then
   ingestion time;
5. nothing left: the asset keeps its value (staleness never clears);
6. the most trusted fresh rank disagrees: `conflict`; then the value the
   asset already shows keeps winning while a source of that rank still
   reports it (`ResolveFrom`): equal sources disagreeing are shown, never
   flapped between. Different ranks disagreeing is precedence, not a
   conflict.

`AttributeSourceRepository.Apply` runs it in one transaction with the asset
rows locked (`SELECT … FOR UPDATE`, id order), writes the changed columns,
flags the deciding row and writes the timeline events, and `AssetService`
then records `asset_state_history` (source and "decided by …" reason),
re-scores criticality/exposure changes and syncs the owner derived from
`owner_ref`.

## Precedence

Attributes are grouped in classes: `identity`, `network` (exposure),
`software`, `ownership` (criticality, owner_ref, data_classification),
`cloud_tags`, `lifecycle`. Each class has a ranked list of source rules or
inherits the organization's default list. A rule names a kind
(`integration`, `scan`, `import`, `feed`) or one source (`scan:nmap`), with
a TTL and a trust flag; an observation takes the rank of the rule naming
its source, else of its kind's rule; no rule or an untrusted rule: it does
not decide. A lock always ranks first.

Built-in defaults (`asset.DefaultReconciliationPolicy`): default list
integration, scan, import, feed; `ownership` integration, import (scan and
feed listed, not trusted); `network` scan, integration, import, feed. TTL
30 days, import 90.

A save that demotes a connector (an integration rule loses trust or its
row, or a source ranks above it that did not before; `DemotesAuthoritative`)
needs step-up re-authentication. After a save the organization's assets are
re-resolved in the background in batches of 200 (`AssetPolicyChanged`);
only values that change get a timeline event (`policy_change`).

`feed` is the kind for passive and published feeds (program feeds, passive
DNS) that a trusted server-side ingest names (`ingest.Options.SourceKind`),
with the bundle sequence as `source_run`.

## Change timeline

`asset_change_events`, partitioned by month on `at` (plus a default
partition for timestamps outside the created months), indexed
`(tenant_id, asset_id, at DESC, id DESC)` and `(tenant_id, at DESC, id DESC)`.
One event when, for one attribute, the shown value changes or the deciding
source changes (`old_value` = `new_value` then). A re-sighting writes none.

| Field | |
|---|---|
| `at` | the deciding source's `observed_at` for a new observation; the time of the change for a lock, release, TTL expiry or policy change |
| `old_value` → `new_value` | `added` / `removed` hold a set attribute's diff (reserved for set attributes) |
| `source_kind`, `source_name`, `source_run` | the deciding source |
| `actor_id` | the person, for a lock or release |
| `reason` | `newer_observation`, `manual_lock`, `lock_released`, `ttl_expiry`, `policy_change`, `source_removed` |
| `flap_count` | a value flipping back and forth between sources within an hour is one event (`asset.ChangeEvent.Coalesces`); locks, releases, TTL expiry and policy changes are never folded |

The `asset-change-timeline` controller (hourly, one replica) creates the
next months' partitions, drops months past retention
(`ASSET_CHANGE_RETENTION_DAYS`, default 400, minimum 30) and once a day
re-resolves every asset with a recorded source, so a value whose deciding
source passed its TTL moves on with reason `ttl_expiry` without waiting for
the next report. Events cascade with the asset (tenant deletion erases
them) and move with it in a merge.

## Who writes observations

```
sensor / import / integration report
   └─ ingest: asset upsert ──► recordAttributes (assets the report may change)
                                   └─ AssetService.ReconcileAttributes ──► Apply
person: create / edit / owner removal / lock / release
   └─ AssetService ──► Apply
```

Ingest no longer fills `owner_ref` or `data_classification` of an existing
asset itself, and an asset a report creates drops the claims its source is
untrusted for.

## API

- `GET /api/v1/assets/{id}/attribute-sources` (`assets:read`, data scope)
- `PUT /api/v1/assets/{id}/attribute-sources/{attribute}/lock` `{value}` (`assets:write`)
- `DELETE /api/v1/assets/{id}/attribute-sources/{attribute}/lock` (`assets:write`)
- `GET /api/v1/assets/{id}/changes` (`assets:read`, data scope): the asset's
  timeline, newest first; filters `attribute`, `source_kind`, `source_name`;
  `limit` (≤ 200) and `cursor` (keyset on `at`, `id`).
- `GET /api/v1/assets/changes` (`assets:read`): the organization feed, only
  assets in the caller's data scope; adds the `tag` filter.
- `GET/PUT /api/v1/organization/settings/asset-reconciliation` (owner/admin):
  `{"default": [{"source": "integration", "ttl_days": 30, "trusted": true}, …],
  "classes": {"ownership": […]}}` (see Precedence); `GET` adds the effective
  policy, the built-in defaults, the classes with their attributes and the
  sources seen (kind, name, last seen, assets). A save that demotes a
  connector needs step-up re-authentication (403 `STEP_UP_REQUIRED`).
- `POST /api/v1/organization/settings/asset-reconciliation/preview`
  (owner/admin): the same body (+ `asset_id`); what it would change, writing
  nothing.

Out-of-scope or another tenant's asset answers 404.

## What is not reconciled here

- Open ports: `open_port` assets, closed only by the same kind of scan
  ([easm.md](./easm.md)).
- Software: `asset_software` with source and confidence
  ([vulnerability-matching.md](./vulnerability-matching.md)).
- Tags, description, name, `properties` (P1: IP addresses, technologies,
  OS as per-source values in the same table).
- Existence: any source keeps an asset active; the lifecycle worker demotes
  it when none has reported it within the threshold.
