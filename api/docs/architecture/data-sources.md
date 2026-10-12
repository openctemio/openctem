# Data provenance: where assets and findings come from

> **Last updated**: 2026-10-05

OpenCTEM records provenance on the asset and on the finding themselves. There
is no separate registry of data sources: the `data_sources`, `asset_sources`
and `finding_data_sources` tables (migration 000014) were never written by any
code path and were dropped in the 2026-10 legacy cleanup together with the
asset-source priority design that keyed on them (RFC-003, withdrawn; see
[asset-source-priority.md](./asset-source-priority.md)).

## Who sends data

| Channel | Direction | Identity | Where it is configured |
|---|---|---|---|
| Sensor (scanner, collector) | push, protocol v2 `/api/v2/sensor/*` | per-sensor key, tenant taken from the key | Sensors ([sensors.md](./sensors.md)) |
| Integration (SCM, cloud, ticketing, vulnerability-management connectors) | pull, server side | per-tenant encrypted credentials | Integrations |
| Import (file upload, CTIS / SARIF) | push through the API | user or `oct_` API key | Assets and findings import |
| Manual | UI / API | user | — |

The tenant always comes from the authenticated principal (sensor key, API key
or session), never from the payload.

## What is stored

**Assets**

| Column | Meaning |
|---|---|
| `discovery_source` | how the asset was first discovered (`sensor`, `dns`, `cert_transparency`, `nessus`, ...); empty for assets created by hand |
| `discovery_tool`, `discovered_at` | the tool and time of that discovery |
| `first_seen`, `last_seen` | first and latest observation; only ingest and integrations move `last_seen` forward (`Asset.MarkSeen`) |

Which source decides an asset's criticality, owner, exposure and data
classification, when several report them, is recorded per source in
`asset_attribute_sources` ([asset-attribute-reconciliation.md](./asset-attribute-reconciliation.md),
RFC-069).

The asset lifecycle worker uses `last_seen` as its clock and
`discovery_source` as provenance when it decides which assets went stale
(`internal/app/asset/lifecycle_worker.go`).

**Findings**

| Column | Meaning |
|---|---|
| `source` | the technique that found it (SAST, DAST, secret, network, ...) |
| `ingest_channel` | who reported it: scanner, integration, collector, manual (enum `source_type`) |
| `tool_name`, `scan_id` | the tool and the scan run |

See [vulnerability-model.md](./vulnerability-model.md) and
[decisions/004-finding-provenance.md](./decisions/004-finding-provenance.md).

## Precedence between sources

When two sources report the same asset, ingest merges the new observation into
the stored asset (`internal/app/ingest/processor_assets.go`); `last_seen` takes
the latest value. Field-level precedence between sources is not configurable.
The per-source record layer planned by RFC-042 (§6.4.5) will add it with its
own tenant-scoped tables.
