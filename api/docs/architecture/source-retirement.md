# Retiring an import source: "Stop using this source"

When an organization decides that a source of findings is junk (a scanner
that reports wrong results, a connector to a system it no longer trusts, a
tool whose uploads were a mistake), it stops using that source. Two things
must then happen, and nothing may be lost:

- new data from the source is refused, and every refusal is recorded;
- the findings **only** that source reported leave the open work, without
  being counted as fixed, and can be brought back.

Findings another source also reported are not touched. Provenance comes from
[finding sightings](finding-sightings.md) ([ADR-004](decisions/004-finding-provenance.md)):
"only this source reported it" is decided from the sightings, never from a
column of the finding.

## What a source is

A source is a sighting key without the scan definition:

| Kind | Keys | Matches the sightings | Matches a report at ingest |
|---|---|---|---|
| `sensor_tool` | the organization's sensor, a tool | `sensor_id` and `tool` (scan runs, tasks, unsolicited reports) | the receipt instance is that sensor and the report's tool is that tool |
| `upload` | a tool | channel `upload` and `tool` | an upload receipt with that tool |
| `connector` | a connector source name | channel `connector` and `sender` | a server-side connector import with that source name |

Tool names compare without case and through the retired-name map, as ingest
names tools. A connector integration that imports through a sensor (the
Tenable.sc connector) is a `sensor_tool` source: the request names the
integration, and the server resolves it to the integration's sensor and the
connector tool (`tenablesc.Service.ConnectorSource`); a client never builds
that selector. CI pipelines have their own retirement (CI coverage).

The SQL function `source_retirement_matches` is the one definition of "this
source" in the database; `sourceretire.Selector.Matches` is the same rule at
ingest.

## What retiring does

`POST /api/v1/findings/sources/retirements` (see API below):

1. A row in `source_retirements` (state `applying`, or `active` for keep
   open). Its insert bumps the organization's ingest policy version
   (trigger), so every ingest worker reloads its policy snapshot: from the
   next report on, the source is refused.
2. The findings are classified (below); those marked `archive` are archived
   in batches of 1,000, each batch in one transaction with its journal rows
   and its timeline entries (the finding-transition trigger, source
   `source_retire`). When no finding is left the state is `active`.

### Classification (preview and archive run the same query)

For every finding the source reported, in this order:

| Class | Rule | Effect |
|---|---|---|
| corroborated | another source reported it, and that source is not itself retired; or the finding has the maximum number of recorded sources (64: another source may be unrecorded); or a person's channel owns it (pentest, manual, bug bounty, red team) | untouched |
| closed | not open | untouched |
| in_progress | open but past `new`/`confirmed` (in progress, fix applied) | kept open: someone works on it |
| secret | a secret finding | kept open: a source that stops reporting a secret has not rotated it |
| engaged | an active ticket link, an open remediation task membership or an assignee | kept open, unless the option includes them |
| severity | its severity was not selected | kept open |
| archive | everything else | archived |

A retired source never corroborates: a finding reported by this source and
by a source retired earlier is archived too.

### Archived = source retired

An archived finding is `resolved` with closure reason `obsolete_source`,
resolution `source_retired` and verification `none` (the same values a
retired CI pipeline writes):

- not fixed: obsolete closures never count as remediated (MTTR, fixed
  counts);
- out of SLA: a closed finding has no running SLA; its deadline is kept;
- filterable by closure reason;
- reopenable by a person, restored by "use this source again", and reopened
  by the normal regression rule when a source that is not retired reports it
  again.

Nothing else changes: text, evidence, sightings, [source records](finding-source-records.md),
comments and history stay (`TestSourceRetirement_ArchiveRestoreExact_DB`).

### Options (the dialog's advanced section)

- `mode`: `archive` (default) or `keep_open` (only block new data);
- `severities`: archive only these severities (default: every one);
- `include_engaged`: also archive `new`/`confirmed` findings with a ticket,
  task or assignee.

Critical findings and findings in the KEV catalog in the archive set need
`confirm_critical`; without it the request is refused with 409
`CONFIRM_CRITICAL_REQUIRED` and the count, computed by the server.

## New data is refused, never dropped silently

`ingest.Service.Ingest` checks the report's source against the policy
snapshot before anything is written (`refuseRetiredSource`). A report of a
retired source applies nothing (no asset, no finding, no sighting); its
receipt counts every finding the report sent under the outcome
`source_retired`, so the receipt reconciles ([ingest receipts](ingest-receipts.md)),
and the output says `source_retired`. A snapshot that cannot be loaded fails
the ingest (the worker retries), so a retired source is never let through by
an error.

Scans that use a retired sensor tool still run (their results are refused);
stopping their dispatch is planned.

## Use this source again (exact restore)

`POST /api/v1/findings/sources/retirements/{id}/reactivate` moves the
retirement to `restoring` (the source is accepted again at once) and
restores the journal (`source_retirement_findings`) in batches: each
finding returns to the status it had (`new` or `confirmed`) while it is
still the closure the retirement made (resolved, `obsolete_source`,
`source_retired`, at the journalled time). A finding a person or another
source changed since is left as it is and counted as `changed`. The journal
keeps the outcome of each row; the retirement keeps the counts and ends
`restored`. The source can be retired again later.

## Large sources and crashes

The request runs batches for up to three seconds and answers `200` when
done, `202` with the progress (`planned_count`, `archived_count`, state)
otherwise. The `source-retirement` controller (one replica, every 15 s)
resumes every retirement left in `applying` or `restoring`. A batch is
idempotent: the classifier excludes closed findings and the journal insert
is `ON CONFLICT DO NOTHING`; the retirement row is locked per batch.

## API

All routes need `findings:sources:retire` (owner and administrator roles,
migration `source_retirements`).

| Route | Does | Step-up |
|---|---|---|
| `POST /api/v1/findings/sources/retirements/preview` | the counts for a source and options | no |
| `POST /api/v1/findings/sources/retirements` | retire (idempotent: a live retirement of the source is returned with `already_retired`) | sensitive |
| `GET /api/v1/findings/sources/retirements` | the retired sources (`include_restored=true` for all) | no |
| `GET /api/v1/findings/sources/retirements/{id}` | one retirement and its progress | no |
| `POST /api/v1/findings/sources/retirements/{id}/reactivate` | use the source again | sensitive |

A source is named by `kind` with `sensor_id`, `tool` or `sender`, or by
`integration_id`.

## Security

- **Authorization**: a dedicated permission (owner and administrator), and
  step-up on retire and restore, as for a bulk close.
- **Data scope**: the source's findings are the whole organization's, so the
  service refuses a caller whose data scope is narrowed (403
  `FULL_DATA_ACCESS_REQUIRED`), for the preview too (its counts are
  organization-wide). An unwired scope resolver refuses (fail closed).
- **Tenant isolation**: the tenant comes from the principal; every statement
  is pinned to it; `sensor_id` must be one of the tenant's sensors and
  `integration_id` one of its connector integrations (404 otherwise); the
  journal has composite foreign keys to the tenant's retirement and finding;
  row-level security policies in shadow mode as on the other tenant tables.
  Tests: `TestSourceRetirement_TenantIsolation_DB`,
  `TestSourceRetire_IngestRefusesRetiredSource` (another tenant's source of
  the same name is not blocked), `TestRetire_AnotherTenantsSensorOrIntegrationIsNotFound`.
- **No time-of-check gap for the confirmation**: the server computes the
  preview again on apply and checks the critical count against it.
- **Audit**: `import_source.retired` and `import_source.restored` (high),
  with the reason, the options, the preview counts and the first 200 finding
  ids.

## Not yet built

- Assets only a retired source created: marked "unverified" and never used
  to widen scope. Needs per-source asset sightings, which do not exist yet
  (ADR-004). A retired source already creates and widens nothing, since its
  reports are refused.
- Stopping the dispatch of scans that use a retired sensor tool.
- A findings filter "only reported by a retired source".
