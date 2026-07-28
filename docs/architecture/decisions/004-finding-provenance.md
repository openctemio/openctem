# 004 — Finding provenance belongs to the sighting, not the finding

**Status:** accepted, not yet implemented
**Date:** 2026-07-28

## The question

"Which findings came from Tenable, and which did our own agent produce?"

It cannot be answered today, and the obvious fix is wrong. This records why, so
the next person does not spend the research again.

## What `findings.source` actually is

`source` encodes **technique** — sast, dast, sca, iac, container, va, easm,
cspm. It does not encode **channel** — who told us. The two axes were conflated
from the start, which is why a Tenable network scan and a DefectDojo sync both
arrived labeled `sast`: neither importer set tool capabilities, and
`detectFindingSource` defaulted to it (fixed in api#373).

Fixing the technique label does not answer the channel question. They are
different columns.

## Why a column on `findings` is the wrong answer

The tempting fix is `findings.integration_id`. It fails on de-duplication.

The fingerprint is `sha256(assetID + ":" + base)`
(`internal/app/ingest/helpers.go:148`) and **`tool_name` is not an input**. The
upsert keys on `ON CONFLICT (tenant_id, fingerprint)`
(`internal/infra/postgres/finding_repository.go:622`).

So the same CVE on the same host, reported by our agent and by a Tenable import,
is **one row**. And the `DO UPDATE` set overwrites `agent_id` (`:636`),
`scan_id` (`:635`) and `tool_version` (`:627`) — but **not** `source` and
**not** `tool_name`.

A merged finding therefore already reports the *first* writer's technique
alongside the *last* writer's agent. Two halves of one row describing two
different scans. A provenance column added beside them inherits exactly that
corruption, and would report one source for a finding that genuinely has two.

Related: `AutoResolveStale` (`:3034`) keys lifecycle on `tool_name` + `scan_id`,
so a shared row gets auto-resolved by whichever tool scanned last.

**Provenance is a property of a sighting.** One finding, many sightings, each
with its own reporter, first-seen, last-seen and confidence.

## The right model already exists, and is a trap in its current state

`pkg/domain/datasource/` models exactly this: `FindingDataSource` with
`sourceType`, `sourceID`, `firstSeenAt`, `lastSeenAt`, `sourceRef`, `scanID`,
`confidence`, `isPrimary`, `seenCount`. Migration `000014_data_sources` created
`data_sources`, `asset_sources` and `finding_data_sources` in April.

It is further along than it looks and less usable than it looks:

- `finding_data_source_repository.go` and `asset_source_repository.go` are
  **fully written — 18 methods each, including `Upsert`** — with **zero
  production callers**. Only two files in the repository import
  `pkg/domain/datasource`, and both are those repositories.
- The `data_sources` **registry has no repository at all**, no service, no
  route, and 0 rows. Nothing can be registered, so `sourceID` is always nil.
- **The landmine:** `Upsert` uses
  `ON CONFLICT (finding_id, source_type, source_id)` (`:187`). The constraint is
  NULLS-DISTINCT, and `source_id` is nil for every manual source — so the
  conflict clause **never fires** and the table grows unbounded duplicates.
  Wiring this naively makes the problem silently worse.
- `asset_sources` has 4 rows. They share a `created_at` to the microsecond, all
  have `source_id IS NULL`, and their values are `github.com/example-corp`,
  `nuclei::recon`. **Hand-seeded fixtures.** No code produces them. Asset
  provenance has never worked either; there is no working analogue to copy.

## Decision

Ship a **channel** column first. Keep the sighting table as the target model.
Never add a single-integration column to `findings`.

`findings.ingest_channel`, reusing the existing `source_type` enum — its values
(`integration`, `collector`, `scanner`, `manual`) already match
`ctis/types.go:47`.

It is the only option that is complete across all four channels, filterable
without a JOIN, and needs **no change to any request contract**:

- DefectDojo already encodes the integration id —
  `internal/app/defectdojo/sync.go:106` sets
  `SourceRef: "defectdojo:" + intg.ID().String()`
- agents already carry a real id from API-key auth
  (`ingest_handler.go:259-288`, stamped at `processor_findings.go:706`)
- the Nessus upload handler knows what it is at the moment it builds findings

Only the *scheduled* Tenable path needs a payload field
(`internal/app/scancoverage/dispatcher.go:22-37`).

Knowing "this came from an integration" is also the prerequisite for reading any
id column added later. Channel first, identity second.

## Implementation notes for whoever picks this up

Two bugs to fix alongside, both found during this research:

- `internal/infra/scanner/nessus/converter.go:94` sets
  `Metadata.SourceType = "scanner"` for what is an **integration**.
- The findings list handler silently ignores the `source_id` query parameter
  that the UI already sends (`ui/.../findings/page.tsx:277,323`).

The write path is wider than it looks: **three duplicated INSERT column lists**
(`finding_repository.go:127`, `:281`, `:596`) plus their argument blocks, the
upsert `DO UPDATE` set (`:620-687`), `Update()` (`:890`), `selectQuery()`
(`:1837`), and `doScan()`/`reconstruct()` (`:1881`, `:2173`). Five non-test
`NewFinding` call sites set the value: `processor_findings.go:692`,
`finding/import.go:181` and `:298`, `finding/vulnerability_service.go:538`,
`compliance/pentest.go:1225`.

For the filter, clone the `Sources` chain verbatim — handler
`vulnerability_handler.go:1625` → input `vulnerability_service.go:1188` →
domain filter `repository.go:577` → predicate `finding_repository.go:2874-2882`.

Facet counts need care: `SourceBreakdown`
(`finding_analytics_repository.go:27`) excludes pentest with a flat
`source != 'pentest'`, while the list query applies a per-user exception
(`finding_repository.go:3005`) that lets campaign members see their own. Using
the analytics endpoint for tab counts would show a number that contradicts the
table beneath it. Derive counts from the list query instead.

## Related

- api#372 — reconciled the three definitions of `findings.source`
- api#373 — stopped recording every unknown scanner as SAST; added `va`
- ui#336 — filters in the URL, multi-select source
