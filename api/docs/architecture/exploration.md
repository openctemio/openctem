# Exploration: how we found this

Design: [RFC-153](../rfcs/RFC-153-exploration.md).

OpenCTEM keeps the facts of discovery in many places: the asset's discovery
lineage, the scope entries, the scan runs and their steps, the targets each
run planned, the ingest receipts and the finding sightings. A story puts the
ones that explain one finding or asset into a short ordered chain, read at
request time. Nothing is copied and no table is added: every step points at
the record it comes from.

## Simplest path

The finding page and the asset page show **How we found this**: a compact
timeline from the scope entry, through the assets the subject was discovered
under, to the scans and sources that reported it. Each step links to its
record. A step the viewer may not see shows as "1 step you cannot see".

Web: `web/src/features/exploration` (`StoryTimeline`, the one component for
every story; `FindingHowWeFoundThis` in the finding page's rail); the asset
page and sheet show it inside their discovery section
(`features/assets/components/asset-lineage-section.tsx`).

## API

| Route | Gate | Answers |
|---|---|---|
| `GET /api/v1/findings/{id}/story` | `findings:read` | the finding's story; not readable as the finding: 404 |
| `GET /api/v1/assets/{id}/story` | `assets:read` | the asset's story; outside the caller's data scope: 404 |

A story is `{subject, steps[], hidden, truncated, more_reports, first_seen_at,
last_seen_at, max_steps}`. Each step has a `kind`, `hidden`, an optional `at`
and one detail object:

| Kind | Detail | From |
|---|---|---|
| `scope_entry` | id, target type, pattern, the chain asset it matches, `excluded_by` (an exclusion in effect that also matches the subject) | the scope entry in effect covering the asset, else its closest visible ancestor (`scope.Explainer`) |
| `asset` | id, name, type, `via` (how it leads down: parent, contains, exposes, serves_certificate, resolves_to), discovery source and tool; `subject` on the asset of an asset story | discovery lineage ([easm.md](easm.md), "Discovery lineage"), at most 5 ancestors |
| `scan` | role (`discovered`, `scanned`, `reported`), run, scan, run status, step name, capability, tool, `relation` | `scan_runs`, `scan_run_steps`, `scans`; for an asset, `scan_run_targets` (the first run that derived it, the latest that planned it) |
| `report` | channel, tool, tool version, sensor, sender, receipt, first and last seen, seen count, backfilled | [finding sightings](finding-sightings.md) (first three reporters, first first; `more_reports` counts the rest); for an asset, the upload receipt that created it (`assets.import_id`) |
| `finding` | id, title | the finding |

Order: scope entry, ancestors from the root down, (asset story: the run that
derived the asset), the asset, then for a finding each reporting source
preceded by the run of its last report and the finding last; for an asset
the upload that created it and the latest run that scanned it.

## Security

- **Same permission as the subject.** The finding story reads the finding
  through `GetFindingWithScope`, the read of `GET /findings/{id}`: tenant,
  data scope, assignee visibility and pentest campaign membership. The asset
  story reads through `GetAssetInCallerScope`. The data scope guard on
  `/findings/{id}/**` and `/assets/{id}/**` answers 404 first.
- **Hidden, never leaked.** A step the caller may not see is returned as
  `{kind, hidden: true}` (an asset keeps its `via`) and counted in `hidden`:
  - an ancestor outside the caller's data scope (the lineage query returns no
    identifying column for it);
  - the finding's asset when the finding is readable but the asset is not (a
    finding assigned to the caller on an asset outside their scope): one
    hidden step, its chain is not walked and no scope entry is tested;
  - a scan run without `scans:read` (the run is not read at all).
  `Story.Seal` strips every hidden step again before it is returned.
- **Scope entries** are evaluated only with `attack_surface:scope:read`, and
  only against the subject and its visible ancestors: an entry matching a
  hidden ancestor would reveal its name. Without the permission no scope step
  is produced and none is counted.
- **Sensors** appear with `sensors:read` only, as in the sightings answer; a
  shared platform sensor is never one of the tenant's sensors.
- **Tenant isolation.** Every query is bound to the caller's tenant on every
  join; a step run joins only through its own tenant-bound run. Another
  tenant's id answers 404.

Tests: `internal/infra/http/routes/exploration_story_db_test.go` (chain,
hidden ancestor, assigned finding on an out-of-scope asset, no `scans:read`,
cross-tenant, gates), `internal/app/exploration/story_test.go`,
`pkg/domain/exploration/story_test.go`.

## Performance

A story is bounded: at most `max_steps` (16) steps, 5 ancestors, 3 reports,
8 runs read in one query, a 5 second budget for all its reads. Every read uses
an index (`TestStoryRepository_ReadsUseIndexes_DB` checks the plans on a
seeded table):

| Read | Index |
|---|---|
| lineage | `assets_pkey`, `idx_asset_rel_target` (bounded recursive walk, existing lineage read) |
| sightings | `ux_finding_sightings_source` |
| runs of the reports | `uq_scan_runs_tenant_id_id`, `scan_run_steps_pkey` |
| runs that derived or targeted an asset | `ix_scan_run_targets_asset` |
| upload that created an asset | `assets_pkey`, `ingest_receipts_pkey` |

## Key files

- `pkg/domain/exploration/story.go`: the story model, `Seal`, `PickReports`.
- `internal/app/exploration/story.go`: composition and redaction.
- `internal/infra/postgres/exploration_story_repository.go`: runs, asset runs, asset receipt.
- `internal/infra/http/handler/exploration_story_handler.go`, `internal/infra/http/routes/exploration.go`.

## Not yet built

- Retest outcomes and evidence items as steps.
- Leads, links and verdicts (the exploration layer): designed in RFC-153, not built.
