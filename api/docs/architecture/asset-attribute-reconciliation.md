# Asset attribute reconciliation

> **Last updated**: 2026-10-09 · Design: [RFC-069](../rfcs/RFC-069-asset-attribute-reconciliation.md)

An asset hears from many sources: sensor scans, file imports, integrations
and people. For the attributes below the platform keeps every source's
latest value and shows the one the organization trusts most, most recently
seen. A person's change is a lock.

## Tracked attributes

| Attribute | Column | Default precedence (after a person's lock) |
|---|---|---|
| `criticality` | `assets.criticality` | integration, import |
| `owner_ref` | `assets.owner_ref` | integration, import |
| `data_classification` | `assets.data_classification` | integration, import |
| `exposure` | `assets.exposure` | scan, integration, import |

A kind left out of a list is **untrusted** for that attribute: by default a
scanner never decides criticality, owner or classification. Default TTLs:
integration 30 days, import 90 days, scan 30 days, a lock never.

## Source kind

Decided by the route the data came through, never by the report:

| Route | Kind |
|---|---|
| asset create / edit, owner removal, lock endpoint | `manual` (a lock) |
| DefectDojo sync (future cloud / inventory connectors) | `integration` |
| finding import (a person's file) | `import` |
| every sensor report, CI run, platform scanner, accepted quarantined report, any other server-side ingest | `scan` |

Code: `ingest.reportSource` (`internal/app/ingest/attributes.go`); only a
trusted binding may set `ingest.Options.SourceKind`.

## Storage

`asset_attribute_sources`: one row per (asset, attribute, source kind, source
name) with `value`, `observed_at` (the report timestamp, never in the
future), `ingested_at`, `confidence`. A row is replaced only by an
observation of the same source seen at the same time or later, so a report
that arrives late never undoes a newer one. Rows cascade with the asset and
move with it in an asset merge (`asset_merge_plan.go`).

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
6. counted rows with different values: `conflict`.

`AttributeSourceRepository.Apply` runs it in one transaction with the asset
rows locked (`SELECT … FOR UPDATE`, id order), writes the changed columns,
and `AssetService` then records `asset_state_history` (source and "decided
by …" reason), re-scores criticality/exposure changes and syncs the owner
derived from `owner_ref`.

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
- `GET/PUT /api/v1/organization/settings/asset-reconciliation` (owner/admin):
  `{"precedence": {"criticality": ["integration","import"]}, "ttl_days": {"scan": 30}}`;
  attributes and kinds left out keep the defaults; `manual` cannot be listed.

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
