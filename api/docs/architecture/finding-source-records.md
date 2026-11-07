# Finding source records: what each source said

A finding is one row per tenant and fingerprint, and the fingerprint does not
include the tool: the same CVE on the same host and port reported by a sensor
scan, a Nessus upload and a connector is one finding
([ADR-004](decisions/004-finding-provenance.md)). Who reported it is recorded
per source in [finding sightings](finding-sightings.md). This page covers
**what** each source reported: its title, text, severity, native identity,
scores and unmapped fields.

Rule (never lose information): a later sighting by another source never
overwrites what an earlier source said. Every source keeps its own latest
record; the finding row is a merged view with a fixed, documented precedence;
the finding page shows each source's values, and where they disagree, side by
side.

## Model

`finding_source_records` holds one row per finding and source:

| Key column | Meaning |
|---|---|
| `channel` | how it arrived: `scan`, `task`, `sensor`, `upload`, `ci`, `connector`, `platform` (the sighting channels); `unknown` only on backfilled rows |
| `sensor_id` | the organization's own sensor; NULL for other channels and for a shared platform sensor |
| `sender` | the CI repository or connector source name; `platform` for a shared sensor; empty otherwise |
| `tool` | the reporting tool |

The key is `UNIQUE NULLS NOT DISTINCT (tenant_id, finding_id, channel,
sensor_id, sender, tool)`: the sighting key without the scan definition, since
two scans by the same sensor and tool are the same source of values.

Each row keeps the source's latest values of every field the finding row
merges:

| Family | Columns |
|---|---|
| Text | `title`, `description`, `snippet`, `recommendation`, `message` |
| Rating | `severity` (normalized), `cvss_score`, `cvss_vector` |
| Type | `type_details` (the source's typed details document) |
| Native identity | `native_vuln_id`, `native_scheme`, `source_meta` (native family, vendor severity, status, detection type, credentialed, lifecycle, solution) |
| Scores and ids | `scores`, `vulnerability_ids` |
| Unmapped | `source_extra`, `location_key` |

and `tool_version`, `first_seen_at`, `last_seen_at` (the source's own
observation time, a file's scan end for an upload; the number of reports is in [finding sightings](finding-sightings.md)),
`clipped` (a value was cut to its cap) and `backfilled`.

**Per source, the newest wins; an empty value never erases.** A repeat of the
same source replaces each value it carries when its observation is not older
than the row's `last_seen_at`; a value it leaves empty keeps the stored one. An
older file of the same source moves only `first_seen_at`.

**Bounded size.** One row per finding and source, at most 64 sources per
finding (`vulnerability.MaxSourceRecordsPerFinding`, as for sightings): a new
source past the cap is not recorded and is logged; an existing one still
updates. Every value is capped before storage and by a column CHECK: title
1 KiB, description 32 KiB, snippet 10 KiB, recommendation 16 KiB, message
4 KiB, type details 16 KiB, and the interop members at the limits of
[finding source interop](finding-source-interop.md) (`SanitizeInteropData`).
A cut value sets `clipped`; the finding page says so.

## Merged view on the finding row

The finding row keeps the fields lists, exports, tickets and notifications
read. Their values follow one rule, never "last writer":

**The primary source is the finding's first reporting tool**
(`findings.tool_name`, set when the finding is created and never changed by a
re-sighting).

1. A sighting by the primary tool refreshes each field it carries (the
   source's own newer text replaces its older text).
2. A sighting by any other tool fills only fields that are empty on the row.
   It never replaces a value.
3. Fields with their own merge keep it: severity and CVSS take the maximum
   (an analyst's override stands), CVE and rule ids are first-wins, tags,
   CWE and OWASP ids are a union, metadata is merged key by key, the secret
   details follow the secret rules, and a VEX statement is replaced by a newer
   statement as a whole.

Rules 1 and 2 cover title, description, snippet, recommendation, message,
`native_vuln_id`, `native_scheme`, `source_meta`, `scores`,
`vulnerability_ids`, `source_extra` and `location_key`. The comparison of tool
names ignores case. A finding without a tool (entered by a person) has no
primary tool: every sighting only fills.

The same rule is applied by the enrichment of an existing finding
(`Finding.EnrichFrom`), by the upsert of two concurrent writers of a new
finding (`findingUpsertConflictSQL`) and by the interop write
(`UpdateInteropBatch`), so the row does not depend on which path a sighting
took. The order of sightings of two tools never flips the row back and forth.

## Write path

`FindingProcessor.processBatch` collects, for every finding it stored or
re-sighted, the values it built from the report (after secret redaction, the
same values the finding row would get) and the interop data. The ingest
service then writes them with the source of the ingest
(`FindingRepository.UpsertSourceRecords`):

- the channel is the receipt channel of the ingest (`ingestreceipt.ChannelOf`
  of the receipt source), and the sender and sensor come from the receipt
  instance, exactly as for sightings;
- the findings are matched by fingerprint under the ingest's tenant, the
  sensor is kept only when it is one of the tenant's own sensors (otherwise
  sender `platform` without an id);
- rows are written in finding id order, in chunks, best effort: a failure is
  logged and never fails the ingest (the finding itself is stored).

Paths that create findings without a report (a person, a pentest, the
platform's version matcher) write no records yet.

## Read path

`GET /api/v1/findings/{id}/source-records` (`findings:read`): the finding's source
records, primary source first, then by first seen. The finding is authorized
like the finding detail (`GetFindingWithScope`: tenant, data scope, pentest
membership); another tenant's id or one outside the caller's scope is 404. The
sensor (id and name) is in the answer only with `sensors:read`. Values are
cleaned on read like the detail's source data (`SourceExtraValue`,
`DisplayPath`, secrets redacted in text).

The answer carries `differences`: the fields whose values differ between
sources (severity, vendor severity, CVSS score, native id, family, status,
solution type, title), computed on the server so every client shows the same
comparison.

The finding page's "Reported by N sources" section
(`web/src/features/findings/components/detail/finding-source-records.tsx`)
shows the differences side by side, one column per source, and each source's
values below, folded.

## Merges

A merge of duplicate findings (mark duplicate, asset merge, re-key) moves the
loser's records to the survivor (`findingMergeRefs`). When both have a record
of the same source, the two are folded into the survivor's row first
(`foldLoserSourceRecords`): the earlier first seen, the later last seen, the
values of the newer record with the older one's filling what it leaves empty.
Nothing a source said is lost by a merge.

## Tenant isolation and threat model

- `tenant_id` on every row, `FOREIGN KEY (tenant_id, finding_id) REFERENCES
  findings (tenant_id, id) ON DELETE CASCADE` (a row can never point at
  another tenant's finding) and `tenant_id` to `tenants` with cascade
  (organization erasure removes them). Row-level security policy in shadow
  mode like the other tenant tables; listed in the tenant-table lint.
- Every statement filters on the tenant; the writer resolves findings and
  sensors only under the ingest's tenant.
- The producer is untrusted: every value is sanitized and capped before
  storage (a hostile sensor cannot grow a finding without bound: 64 sources,
  capped values). Values are shown escaped, only in the finding detail; lists,
  exports and tickets do not read the table.
- A secret finding's snippet is stored after the same redaction as the finding
  row; the read redacts secrets again.

## Backfill

Existing findings have no records. The `finding-source-backfill` operator
command (a link to the server binary, like `refingerprint`) creates one record
per finding from the values on the finding row, attributed to the finding's
most recent sighting (`finding_sightings`), marked `backfilled` ("From earlier
records"). The row's values may mix earlier sources; that is why they are
marked. Findings without a sighting (entered by a person) get none.

- dry run by default: it reports per tenant and channel what it would create;
  `-apply` writes, in batches of `-batch` findings (default 500), one short
  transaction each, `ON CONFLICT DO NOTHING`, so it can run on a live system
  and be re-run;
- `-tenant <id>` limits it to one organization; `-json` prints the report.

## Simplest path

Nothing to configure. A person opens a finding that several tools reported
and sees "Reported by 3 sources", the fields they disagree on side by side,
and every source's full record one click away. The finding row keeps reading
the same for lists and tickets; it no longer changes with whichever tool ran
last.

## Not yet built

- A per-organization source precedence for the merged view (choose which tool
  is primary per field).
- Filters on source values ("vendor severity differs").
- Export of the per-source records.
- Showing each source's type details document (stored, not yet in the read).
- Records for findings the platform's version matcher creates (it books
  sightings but builds no report).
