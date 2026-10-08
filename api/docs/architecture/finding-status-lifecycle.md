# Finding status lifecycle

Every finding, whatever its source (scanner, import, CI, pentest), takes one
status from one set, and every write of `findings.status` follows one
lifecycle.

## The status set

| Status | Category | Meaning |
|---|---|---|
| `new` | open | Reported, not triaged |
| `confirmed` | open | A real issue that needs a fix |
| `in_progress` | in progress | Being fixed |
| `fix_applied` | in progress | Marked fixed; a scan, a retest or a security reviewer still has to verify it |
| `validated_fixed` | in progress | A validation re-check no longer observes it; a person closes it |
| `not_observed` | in progress | Not reported lately and no coverage proof: stale, not fixed ([finding-status-not-observed.md](finding-status-not-observed.md)) |
| `resolved` | closed | Verified fixed |
| `false_positive` | closed | Not a real issue (approval) |
| `accepted` | closed | Risk accepted, with an expiry (approval) |
| `duplicate` | closed | Folded into another finding |
| `draft`, `in_review` | open, hidden | Pentest finding before publication; left out of dashboards and the Open lens |

The list is `vulnerability.AllFindingStatuses()`; the database CHECK
`chk_findings_status` (migration `001377`) and the web registry
(`web/src/features/findings/types/finding.types.ts`, labels in en and vi) hold
exactly the same values, and tests on each side pin them.

How a finding was closed is its `resolution_method`, not a status:
`scan_verified`, `retest_verified`, `security_reviewed`, `admin_direct`,
`source_mitigated`, `source_retired`, `vex_not_affected`. A pentest finding
whose retest passed is `resolved` with `retest_verified`.

`open` is a lens and a category of the findings list (`state=open`), never a
status. The API refuses an unknown status with a 400, in a status change and in
a list filter; it never maps one to another.

## The lifecycle

`pkg/domain/vulnerability/status_lifecycle.go` holds three maps:

- `ValidStatusTransitions`: the moves a person may make (triage, work state, a
  verified close with `findings:verify`, a disposition through approval, a
  reopen).
- `PlatformStatusTransitions`: the extra moves only the platform makes, each on
  evidence a person does not hand over: a covered scan or a source's own
  "mitigated" state closes open work (`new`/`in_progress` -> `resolved`), a
  stale source or expired feature branch marks open work `not_observed`, a VEX
  `not_affected` statement marks it `false_positive`, a retest moves
  `fix_applied`/`not_observed` to `validated_fixed`, an approved suppression
  rule gives a new finding its disposition and lifting the rule returns it to
  `new`.
- `PentestStatusTransitions`: a pentest finding's lifecycle over the same
  statuses plus `draft` and `in_review` (`confirmed -> in_progress ->
  fix_applied -> resolved`, regression `resolved -> in_progress`); campaign roles
  gate each move (`pentest.PentestStatusTransitionRoles`).

## Enforcement on every write path

- Entity: `Finding.TransitionStatus` (a person), `ApplyPlatformTransition`
  (platform), `ApplyPentestTransition` (pentest); `MarkAsDuplicate` checks the
  map. There is no unchecked status setter.
- Bulk SQL writes (coverage and default-branch auto-resolve, source-mitigated
  resolve, VEX, stale-source and branch expiry, regression reopen, suppression
  lift and re-link) take their from-states from
  `internal/infra/postgres/finding_status_sql.go`, which renders them from the
  domain sets and checks them against the platform map when the package loads:
  a list that drifts stops the server at start and fails every test.
- `UpdateStatusBatch` and `BulkUpdateStatusByFilter` (bulk change, verify or
  reject by filter, approvals, acceptance expiry) only touch rows whose current
  status a person may move to the target, so a finding that changed since the
  request is left alone.
- The retest settle refuses a decision that is not a lifecycle move and rolls
  back. An approval is refused when the finding can no longer reach the
  approved status; an expired acceptance reopens a finding only while it is
  still `accepted`.
- `finding_status_sql_test.go` pins every SQL statement that writes
  `findings.status`; a new one fails the test until it uses a lifecycle list.

Deliberately outside the maps: folding one finding record into another (the
tombstone becomes `duplicate`; the survivor keeps the more advanced triage
state of the two), which is an identity merge, not a lifecycle move.

## Upgrade

Migration `001377` maps stored values of the retired pentest statuses
(`remediation` -> `in_progress`, `retest` -> `fix_applied`, `verified` ->
`resolved` with `resolution_method = retest_verified`, `accepted_risk` ->
`accepted`) and `open` -> `new`, in `findings`, `pentest_findings`, approvals
and retests, then adds the CHECKs (`NOT VALID`, then `VALIDATE`). It is
idempotent. The down migration restores the old CHECK; mapped rows keep their
canonical status.
