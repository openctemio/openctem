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
`chk_findings_status` (migration `001378`) and the web registry
(`web/src/features/findings/types/finding.types.ts`, labels in en and vi) hold
exactly the same values, and tests on each side pin them.

How a finding was closed is its `resolution_method`, not a status:
`scan_verified`, `retest_verified`, `security_reviewed`, `admin_direct`,
`source_mitigated`, `source_retired`, `vex_not_affected`. A pentest finding
whose retest passed is `resolved` with `retest_verified`.

## Open, fixed, dispositioned, closed: one definition

Every count, metric, list and job asks "open?" or "fixed?" the same way
(`pkg/domain/vulnerability/status_sets.go`):

| Set | Statuses | SQL predicate |
|---|---|---|
| Open | `new`, `confirmed`, `in_progress`, `fix_applied`, `validated_fixed`, `not_observed` | `vulnerability.OpenStatusSQL(col)`; in the database `is_open_finding_status(status)` |
| Fixed | `resolved` | `vulnerability.FixedStatusSQL(col)` |
| Dispositioned | `false_positive`, `accepted`, `duplicate` | `vulnerability.DispositionedStatusSQL(col)` |
| Closed | Fixed and Dispositioned | `vulnerability.ClosedStatusSQL(col)` |

Pentest `draft` and `in_review` are in no set (they are not published).
`ActiveFindingStatuses()` is the open set. The findings tabs, the dashboards,
the risk snapshot (open count, closed today and MTTR count only fixes), asset
and asset-group finding counts, repository branch counters, active CVEs, the
grouped view, KEV escalation, SLA escalation and the threat-intel exposure
lists all use it. The web console's copy is
`web/src/features/findings/lib/list-defaults.ts`.

`TestNoHandWrittenFindingStatusLists` (`internal/infra/postgres`) fails when Go
code hand-writes a SQL list of two or more finding statuses; the few lists that
are a different set (a pentest report's published findings, the mean time to
validate population) are allow-listed there with their reason, and
`TestFindingStatusSets_SQLMatchesGo` pins the SQL function to the Go set.

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
  rule gives a new finding, and on approval the open findings it matches
  (`SuppressionApplyFromStatuses`), its disposition, and lifting the rule
  returns them to `new` (`suppression-rules.md`).
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
  approval, lift and re-link) take their from-states from
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

## Every move is on the timeline

A finding's timeline (`finding_activities`) explains every status change, in
the same transaction as the change.

- **Platform writers** name themselves for their transaction with
  `set_config('openctem.transition', <json>, true)` (Go:
  `findingTransition` / `vulnerability.StatusTransition` in
  `internal/infra/postgres/finding_transition.go`). The trigger
  `trg_findings_record_transition` (migration `002153`) then writes one entry
  per finding the transaction moves: the old and new status, what the
  resolution was before (`previous_resolution`, `previous_resolution_method`,
  `previous_resolved_by`, `previous_resolved_at`), a reason code, the source,
  the actor and evidence references (scanner, scan or command, pipeline, rule,
  statement). The move and its entry commit or roll back together.
- Covered by it: coverage and default-branch auto-resolve and the source's own
  "mitigated" state (`auto_resolved`), scan re-detection (`auto_reopened`;
  `observed_again` for a stale finding), template drift, feature-branch
  expiry, CI pipeline stale and retired, VEX in scan reports and VEX
  documents, the software vulnerability matcher, correlation link and release,
  taint-source suspension, suppression re-link, and the bulk verify / reject by
  filter.
- **Application paths acting for the platform** (validation verdicts, the IOC
  correlator, workflow `update_status`, auto-assign to owners) attach the
  transition to the request context (`vulnerability.WithStatusTransition`);
  `FindingRepository.Update` and `UpdateStatusBatch` then write the move and its
  entry in one transaction. A workflow is recorded as `workflow:<id>` (before,
  its entry failed on an invalid actor id).
- Evidence such as the scan behind an auto-resolve travels in the context
  (`vulnerability.WithTransitionEvidence`).
- Without a named transition the trigger writes nothing: a person's change is
  recorded by its service with the person as the actor.
- `TestFindingStatusSQL_EveryStatusWriteIsOnTheTimeline` fails when a file that
  writes `findings.status` records no timeline entry.

## Risk acceptance end

An accepted risk always ends; a false positive does not (it is re-reviewed
instead).

- **One value, one meaning.** `finding_status_approvals.expires_at` is the end
  of the decision the request asks for. A request for `accepted` gets 90 days
  when it names no end and is refused with an end in the past or more than a
  year ahead; a request for `false_positive` is refused when it names an end.
  A pending request has no separate approve-by deadline: once the requested
  end has passed it can no longer be approved (it would accept nothing) and is
  submitted again with a new end. Approving an older `accepted` request that
  has no end gives it the 90-day default from the approval.
- **On the finding.** Approving `accepted` stores the end in
  `findings.acceptance_expires_at` in the same statement as the status
  (`FindingRepository.AcceptUntil`). A finding that an approved accepted-risk
  or won't-fix suppression rule closes takes the rule's `expires_at` when the
  finding-rule link is recorded (`SuppressionRepository.RecordSuppression`,
  same tenant only); a rule without an expiry leaves it empty, and the rule's
  own expiry lifts the suppression.
- **Cleared on leaving accepted.** The trigger
  `trg_findings_clear_acceptance_expiry` empties the column on any row that is
  not `accepted`, whatever path wrote the status, so a later accept starts
  clean.
- **Who reads it.** The CI gate honors an accepted finding only until its end
  (`cirun.honored`), even before the hourly approval-expiration controller
  reopens it. Threat models read it as the acceptance horizon.

Migration `002119` adds the trigger and fills the column for findings already
accepted, from their latest approved acceptance request or their suppression
rule. Findings accepted with no end anywhere stay empty.

## AI false-positive proposals

AI triage may **propose** a false positive; it never decides one.

- When a triage completes with a false-positive likelihood of at least 0.9
  on a **medium or low** finding, the finding service creates a **pending**
  `finding_status_approvals` request for `false_positive`. The model's
  rationale is the justification, prefixed with the likelihood, with control
  characters dropped and capped at 1000 characters. The finding does not
  change.
- The request has no person as requester: `requested_by` is NULL and
  `requested_by_actor` is `ai_triage` (a CHECK allows only that value, and
  only with `requested_by` NULL). For the four-eyes rule it was requested by
  nobody: any approver may approve or reject it, and an approval always needs
  a person (`Approval.Approve` refuses a zero approver).
- It is never made for critical or high findings, and never auto-approved.
  It is not repeated while any request is pending for the finding (a partial
  unique index also stops two workers racing), nor after a person rejected an
  AI proposal for that finding.
- Finding text and code are hostile input for the model. A triage whose
  output needed review (coerced fields, or prompt-injection markers in the
  finding, which also cap the likelihood below 0.8) proposes nothing. The web
  shows the proposal as "Proposed by AI triage" and renders the justification
  as plain text.
- It runs only where AI triage runs: the `ai_triage` module enabled and an AI
  mode configured for the organization.

Key files: `internal/app/finding/vulnerability_service.go`
(`ProposeFalsePositiveFromAI`), `internal/app/aitriage/service.go`
(`proposeFalsePositive`), `pkg/domain/vulnerability/approval.go`
(`NewActorApproval`), migration `002131`.

## Four-eyes on exposure dispositions

Accepting the risk of, or marking a false positive, an exposure or a leaked
credential (`/exposures/{id}/accept`, `/false-positive`, and the same routes
under `/credentials`) is the same disposition a finding reaches only through an
approval. For a **high or critical** item it takes two people:

1. The first approver's call stores a pending request in
   `exposure_disposition_requests` (one per exposure) and answers 202 with the
   exposure unchanged and its `pending_disposition`.
2. A different approver's call for the same disposition applies it (200). A
   call for the other disposition is refused while one is pending.
3. `POST /{id}/disposition/reject` drops the pending request; when the
   requester calls it, the request is canceled.

The requester never confirms their own request. The organization owner may,
only when nobody else in the organization holds every permission the route
requires (counted as active owners, admins and members whose roles grant
them); that approval applies at once and is audited Critical
(`exposure.disposition_self_approved`). Every request, approval and rejection
is in the audit log (`exposure.disposition_*`) and the state change keeps both
reasons in the exposure's state history. Low and medium items keep the
one-step path. A request is created only for an exposure of the caller's
tenant and data scope (the insert selects the exposure under the tenant).

Key files: `pkg/domain/exposure/disposition.go`,
`internal/app/exposure/disposition.go` (`DispositionGate`),
`internal/infra/postgres/exposure_disposition_repository.go`, migration
`002132`; web `features/exposures/components/pending-disposition.tsx`.
The credentials page has no accept or false-positive control yet; its API
responses carry `pending_disposition` the same way.

## Upgrade

Migration `001378` maps stored values of the retired pentest statuses
(`remediation` -> `in_progress`, `retest` -> `fix_applied`, `verified` ->
`resolved` with `resolution_method = retest_verified`, `accepted_risk` ->
`accepted`) and `open` -> `new`, in `findings`, `pentest_findings`, approvals
and retests, then adds the CHECKs (`NOT VALID`, then `VALIDATE`). It is
idempotent. The down migration restores the old CHECK; mapped rows keep their
canonical status.
