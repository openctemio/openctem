# Compliance checks

Design: [RFC-152](../rfcs/RFC-152-finding-practices.md) (finding practices,
compliance). Related: [finding practices](finding-practices.md),
[finding import](finding-import.md).

A benchmark check result (CIS, DISA STIG, a vendor hardening guide; finding
type `compliance`) is the **state of one control on one asset**, not a
vulnerability. The platform keeps the latest result of every control with
its evidence, keeps every change as history, and keeps a finding open only
while a control fails.

## Results

| Result | Scanner word (Nessus) | Finding | Pass rate |
|---|---|---|---|
| `fail` | FAILED | opened or kept open | counts as failed |
| `manual` | WARNING | opened (a person judges it) | left out, shown |
| `pass` | PASSED | none; resolves the open failure of the same check (an upload) | counts as passed |
| `not_applicable` | SKIPPED | none | left out, shown |
| `error` | ERROR (the check could not run) | none | left out, shown |

The CTIS kind carries pass, fail, review and not_applicable. An importer says
why a not_applicable result was not evaluated in
`extensions["io.openctem"].compliance_outcome` (`error`, `skipped`); without
it, the scanner's own word in `source_extra.compliance-result` (`ERROR`)
keeps the error, so an error is never folded into not applicable
(`compliancecheck.ResultOf`).

## Check state (shipped)

- `compliance_check_states`: one row per (tenant, asset, benchmark, control):
  benchmark key, name and version, framework, control id and name, benchmark
  level, latest result, the scanner's severity, the evidence (actual value,
  expected value, the scanner's message, the audit file; each at most 4 096
  characters), the tool, the finding of a failure (kept when the control
  passes later), first seen, last checked, last changed.
- `compliance_check_results`: the history, append-only: the first
  observation of a control and every later change of result or evidence,
  with the previous result. A file that arrives late (observed before the
  stored state) is written to the history only and never moves the state;
  the same observation twice writes nothing.
- The benchmark key is the benchmark's name lowercased with every run of
  other characters one dash (`compliancecheck.BenchmarkKey`); the name comes
  from `source_extra.compliance-benchmark-name`, else the framework. The
  control is the compliance block's control id, else the rule id.
- `findings.compliance_level` (1 to 3, NULL when unknown) and the state's
  level come from the benchmark profile (`Level 1 - Server`, `L2`, `CAT II`;
  `vulnerability.ParseComplianceLevel`).
- Ingest (`internal/app/ingest/compliance_checks.go`) records every compliance
  result of a report, for every channel (upload, scan, CI, connector). A
  pass, a not-applicable and an error are no finding and no sighting; the
  receipt counts them as `compliance_passed` and `compliance_state`. A failure
  and a warning go through the finding pipeline as before and their state
  links the finding.
- A pass resolves the open failure of the same host and check on an upload
  (the file's own coverage, the organization's closing mode and the guards
  of [finding import](finding-import.md)); the state keeps the link to the
  resolved finding and its history keeps the failure's evidence. A platform
  scan closes findings only through the per-command coverage evaluation of a
  protocol v2 run; a compliance pass from a scan is recorded as state and does
  not close by itself yet (planned).
- Merging assets moves the states the kept asset lacks (the kept asset's own
  state of a control wins) and the whole history of both
  (`asset_merge_plan.go`).

## Posture (shipped)

`compliance_posture` holds, per (tenant, asset, benchmark), the number of
controls per result and the failures that are excepted (their finding is
accepted or a false positive). It is precomputed:
`compliance_posture_recompute(tenant, asset)` rebuilds one asset's rows, and
the dashboard maintainer runs it for an asset marked in `dash_dirty_assets`
with reason 32 (check states changed, set by every state write) or 1 (its
findings changed, so an acceptance becomes an exception).

Pass rate = passed / (passed + failed); not applicable, error and manual are
shown beside it and never counted. Excepted failures stay in the failed count
and are shown separately.

## Priority (shipped)

A compliance finding's severity and class come from the benchmark level and
its asset, never from the scanner (`vulnerability.ComplianceSeverity`,
`vulnerability.ClassifyCompliance`):

| Result | Level 1 or unknown | Level 2 or 3 |
|---|---|---|
| failed | medium | low |
| warning (manual) | low | low |

- A critical asset (crown jewel, or criticality critical) or the production
  environment raises a failure by one band; both together still one band.
  Internet exposure changes nothing: a hardening control does not measure
  exposure. The highest a compliance finding gets by itself is high.
- Class: high is P2, everything else P3. Exploitation signals (KEV, a
  reproduced validation) and the exploitation floor never apply to a
  benchmark check; a tenant priority rule may still raise one, and the
  attribution cap applies. With the compliance SLA windows a level 1 failure
  on a normal server is medium, P3, 180 days.
- Ingest sets the severity of every new or re-sighted compliance failure
  before it is classified and written (one tenant-pinned read of the batch's
  assets: crown jewel, criticality, environment). An analyst's severity
  override stands. A re-sighting never lowers a stored severity (the
  re-sighting rule keeps the higher one), so findings stored before this
  change keep the scanner's severity until the `compliance-checks` command
  re-classifies them.
- The scanner's severity is kept on the check state (`scanner_severity`) and
  in the sighting's source data.
- Filter: `compliance_level` (1, 2, 3; in, not in, at least, at most, empty)
  on every findings list, saved view and export.

## Reads (shipped)

All need `findings:read` and run in the caller's data scope (resolved fail
closed: a member with no scope row sees nothing), pinned to the tenant.

| Route | Answers |
|---|---|
| `GET /api/v1/findings/compliance/benchmarks[?asset_id=]` | per benchmark over the caller's assets (or one asset): assets checked, assets failing, controls per result, pass rate; from the precomputed posture, at most 200 benchmarks, failing first |
| `GET /api/v1/findings/compliance/benchmarks/{key}/controls?result=&q=` | a benchmark's controls, failed first, with assets per result and the pass rate; paged (100 per page at most) |
| `GET /api/v1/findings/compliance/benchmarks/{key}/assets?control=&result=` | one control's state on each asset: result, evidence, the scanner's severity, the finding and its status, last checked and last changed; failed first, paged |
| `GET /api/v1/findings/{id}/compliance-history` | the control a finding fails, its current result and every change, newest first (at most 200); the finding is read with the detail's access check first (404 outside scope) |

Evidence in responses has secrets redacted (`safetext.RedactSecrets`). An
asset outside the caller's scope reads as no benchmark, never as an error.

## Remediation per control (shipped)

A compliance finding's remediation key is
`control:<benchmark key>:<control id>` (key rules version 5): one group per
control fixes every asset that fails it. A compliance finding never gets an
`upgrade:` or `sol:` key, and without a benchmark control it gets no key. The
key reads the control from the finding's check state.

## Existing findings: the `compliance-checks` command (shipped)

Compliance findings stored before check state existed are moved by an
operator command (a link to the server binary in the API image,
`api/internal/tools/compliancechecks`). It considers every open compliance
finding; closed findings are never touched.

- It records the state of each finding's control (history source
  `backfill`), reading the benchmark, profile, policy value and error from
  the finding's source data; an error stored as not applicable is read back
  from the scanner's own word.
- A failure or a warning is re-classified with the write path's functions:
  severity from the level and the asset, class from the severity, the level
  column filled. An analyst's severity override and a manual class override
  stand. A timeline entry (`severity_changed`, reason `compliance_policy`)
  records each change.
- A finding that is no failure (passed, not applicable, could not run) is
  resolved with the closure reason `reclassified_check_state` (never counted
  as fixed, `resolution` `compliance_<result>`), with a timeline entry and an
  audit log entry (`finding.status_changed`, the run id) per finding, plus one
  `findings.reclassified` entry per tenant and run with the counts.
- **A dry run is the default**: a read-only connection and aggregates only,
  per tenant: open findings per result, severity and class moves, closes per
  result, control states to record, per benchmark. No finding id or content
  is printed.
- `-apply -undo <file>` creates the undo file (never overwritten) and writes
  every changed row's previous status, severity, class and level before the
  page that changes it commits. Keyset pages of 2 000 (`-batch`), one
  transaction each; a row changed since it was read is left alone; a rerun
  changes nothing. `-tenant <id>` limits the run to one tenant; `-json`
  prints the report as JSON.

Order on an existing installation (each a dry run first; the production apply
is the owner's decision): `finding-practice -apply` (practices),
`compliance-checks -apply -undo <file>`, then `finding-practice -sla -apply
-undo <file>` (compliance deadlines from first detection with the new
classes). The remediation key backfill derives the `control:` keys once the
states exist.

```
compliance-checks                          # dry run, every tenant
compliance-checks -tenant <id> -json       # dry run, one tenant, JSON
compliance-checks -apply -undo undo.csv    # write (owner's go on production)
```

## Security

- Every read and write is pinned to the tenant: the recorder reads the
  tenant's assets and findings only, so another tenant's asset is refused
  and another tenant's finding is never linked, even with the same
  fingerprint (`TestComplianceCheckRecord_TenantPinned_DB`).
- Evidence is bounded and stored as the importer gives it; the Nessus importer
  redacts credentials from the actual value before it reaches the platform.
- The command reads and writes one tenant at a time with every statement
  pinned to it (`TestRun_TenantIsolation_DB`); a dry run cannot write (the
  connection is read-only at the server); the report holds counts only.
- Reads: tenant-pinned SQL with the caller's data scope on the state's
  asset; DB tests with an owner, a member scoped to one asset, a member
  without scope and another tenant's checks of the same benchmark
  (`TestComplianceChecks_ReadsWithinScope_DB`). No new permission.

## Key files

- `api/pkg/domain/compliancecheck/check.go` (results, benchmark key, evidence)
- `api/pkg/domain/vulnerability/compliance_level.go`
- `api/internal/app/ingest/compliance_checks.go`
- `api/internal/infra/postgres/compliance_check_repository.go`
- `api/migrations/*_compliance_check_state.sql`
- `api/pkg/domain/remediation/group.go` (`control:` key)
