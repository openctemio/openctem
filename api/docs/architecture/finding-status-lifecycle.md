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

## Closure reason and verification

Why a closed finding is closed, and how a closing claim was proven, are two
fields beside the status (`pkg/domain/vulnerability/closure.go`), never a
status. A closed finding always has a `closure_reason`; an open one never has
one. The reasons are a closed set per status, aligned with the VEX
justifications so they export without translation:

| Status | `closure_reason` | Counts as remediated |
|---|---|---|
| `resolved` | `fixed`, `mitigated` | yes |
| `resolved` | `obsolete_asset`, `obsolete_source`, `obsolete_rule` (the finding went away without a fix) | **no** |
| `false_positive` | `component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`, `detection_error`, `test_or_example_code` | no |
| `accepted` | `risk_accepted`, `compensating_control`, `wont_fix`, `no_fix_available` | no |
| `duplicate` | `duplicate`, `correlated` | no |
| any closed | `unknown`: closed before reasons existed, or by a writer that knows none; never guessed | `resolved`/`unknown` still counts, as it always did |

`verification` says how a resolve (and a false positive the platform or an
approval established) was proven: `covered_scan`, `retest`, `source_reported`
(a scanner's own "mitigated" state, a new installed version, a changed
advisory), `vex_statement`, `security_review` (`findings:verify` with the
verification checklist, or a four-eyes approval of a false positive),
`attested` (a `findings:verify` holder closed it without the checklist),
`none` (an obsolete closure) or `unknown`.

Who writes what:

| Writer | Closure |
|---|---|
| Covered scan (coverage auto-resolve, repository default branch) | `fixed` / `covered_scan` |
| Retest | `fixed` / `retest` |
| Source "mitigated" state | `fixed` / `source_reported` |
| Software matcher: new installed version / advisory changed | `fixed` / `source_reported`; `false_positive` `detection_error` / `source_reported` |
| VEX statement or VEX document | `fixed` or the statement's justification / `vex_statement` |
| CI pipeline retired | `obsolete_source` / `none` |
| License policy no longer flags the package | `obsolete_rule` / `none` |
| Person resolve (`PATCH /status`, bulk, verify) | `fixed` (or `mitigated`, `closure_reason` in the request) / `security_review` with the checklist, else `attested` |
| Approved false positive or accepted risk | the reason named in the request (`closure_reason`, required) / `security_review` for a false positive |
| Accepted-risk suppression rule | `risk_accepted` |
| Duplicate, correlation | `duplicate`, `correlated` |

The database keeps the pair consistent for every writer
(`trg_findings_settle_closure`, migrations `finding_closure_*`, run after every trigger that changes the status): it
clears both on an open status, drops a value left over from the previous
status that does not fit the new one, and fills the status default when a
writer names none. `chk_findings_closure` (via `finding_closure_valid`, pinned
to the Go tables by `TestFindingClosureValidMatchesGo`) refuses a reason of
another status.

MTTR, the risk snapshot's closed-today and MTTR, the executive summary, the
risk velocity fix count and the mean time to remediate after validation count
**remediated** findings only (`vulnerability.RemediatedSQL`): resolved and not
obsolete.

A pentest finding whose retest passed is `resolved` with `fixed` / `retest`.

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

## What counts as a regression

`is_regression`, `reopen_count` and `last_reopened_at` are set by the trigger
`trg_findings_mark_regression` when a `resolved` finding reopens on
**evidence**: a scan reports it again, a retest fails, a fixed VEX statement is
withdrawn, the software matcher or a license policy flags it again, an
indicator matches it. A person moving a finding back from `resolved` (the
drawer's Undo, a correction, a bulk change) is not a regression: the status
endpoint and the bulk change mark their transaction
`openctem.person_move` (`vulnerability.WithPersonMove`), and the trigger skips
it (migration `002205`). The drawer offers Undo only for moves that do not
close the finding; reopening a resolved finding is a deliberate move from the
status control.

## Every move is on the timeline

A finding's timeline (`finding_activities`) explains every status change, in
the same transaction as the change.

- **Platform writers** name themselves for their transaction with
  `set_config('openctem.transition', <json>, true)` (Go:
  `findingTransition` / `vulnerability.StatusTransition` in
  `internal/infra/postgres/finding_transition.go`). The trigger
  `trg_findings_record_transition` (migration `002180`) then writes one entry
  per finding the transaction moves: the old and new status, what the
  resolution was before (`previous_resolution`, `previous_closure_reason`, `previous_verification`,
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

## Automatic signals never reverse a decision

A false positive, an accepted risk or a duplicate is a person's decision
(approved, for the first two). No automatic signal moves it:

- a changed taint source and an indicator-of-compromise match raise a
  **review flag** instead (`finding_decision_reviews`, migration `002154`,
  reasons `taint_source_changed` and `ioc_match`), with a `decision_review`
  timeline entry in the same transaction and an audit event; one open flag per
  finding and reason; it clears when the finding's status changes;
- an IOC match still reopens a finding closed as `resolved` (the match is
  evidence it is not fixed).

## Duplicates name their canonical finding

A duplicate is a tombstone of another finding: `duplicate_of` is always set
(CHECK `chk_findings_duplicate_has_target`, migration `002151`). It is made only
by `POST /api/v1/findings/{id}/duplicates` (`findings:triage`, plus
`findings:approve` when either side carries a decision), by correlation and by
merges. `PATCH /findings/{id}/status`, the bulk status change and the workflow
`update_status` action refuse `duplicate` with a 400 naming that route
(`vulnerability.ErrDuplicateNeedsCanonical`, enforced in
`Finding.TransitionStatus` and `ApplyPlatformTransition` too); the drawer's
status control does not offer it (Mark duplicate picks the canonical finding).

When a canonical finding is deleted its duplicates lose `duplicate_of`
(`ON DELETE SET NULL`); the trigger `trg_findings_reopen_orphaned_duplicate`
reopens each to `confirmed` with a timeline entry instead of failing the delete.
Migration `002151` repaired existing orphan duplicates the same way (status
`confirmed`, timeline reason `duplicate_link_missing`).

## The same claim and close rules on every route

Marking a fix applied and resolving follow the same rules on every route a
person can use: the dedicated actions (`/actions/fix-applied`,
`/actions/verify`), `PATCH /findings/{id}/status`, the bulk status change,
and remediation group and campaign resolves (which use the bulk path).

- **Fix applied:** `findings:fix_apply`, a note, and the finding must be the
  person's: the assignee, a member of an assigned group, or an owner of the
  asset (`FindingActionsService.FixAppliers`, wired into the status service
  with `SetFixApplierCheck`). The bulk paths skip, and report, each finding
  that is not theirs.
- **Resolved:** `findings:verify` (unchanged). A resolve backed by a complete
  verification checklist is verified by `security_review`; any other person's
  resolve is `attested` and needs a note. A bulk resolve reads no
  checklist, so it always needs one.
- **Callers without a user** (an organization API key) get the same rules,
  never an exemption: they need the permission and the note, and cannot claim
  a fix at all (`ErrFixApplyNotAPerson`). Only an explicit system move, a
  workflow's `update_status` (a transition with source `workflow`), is exempt.
- Errors: `ErrFixApplyRequiresPermission`, `ErrFixApplyNotYours` and
  `ErrFixApplyNotAPerson` (403), `ErrNoteRequired` (400).
- The web asks for the note in the drawer's status control, the bulk resolve
  dialog and the group and campaign resolve dialogs.

## Mark fixed: remediation group and campaign resolves

A remediation group or campaign "resolve" is a **mark fixed**, never a close
(`BulkUpdateStatusInput.WalkToFixApplied`):

- Every open, in-scope, non-pentest member takes the legal person steps to
  `fix_applied` (`vulnerability.FixClaimPath`: `new → confirmed → in_progress
  → fix_applied`, `confirmed`/`not_observed → in_progress → fix_applied`).
  Each step is a separate status write that accepts only that step's exact
  predecessors (`vulnerability.FixClaimStepFrom`, through
  `UpdateStatusBatchFrom`): a finding closed while the claim runs (for example
  an approved false positive) is never walked back open, although the
  lifecycle allows `confirmed` from closed statuses. The status history
  records every step. The findings are read back afterwards: one that
  changed in between is reported with its current status.
- A member already `fix_applied` is skipped, never rewritten (its earlier
  note and actor stay). A `validated_fixed` member is refused: a reviewer
  verifies it.
- The fix claim rules above apply (`findings:fix_apply`, a note, only the
  person's own findings). The group and campaign services refuse a missing
  permission or note before reading the group or spending the bulk budget.
- A target of `resolved` is refused with 400 (`ErrGroupResolveClosesNothing`,
  `ErrCampaignResolveClosesNothing`), even for a `findings:verify` holder: a
  group shares a fix, not the proof that each finding is gone.
- A proof-of-fix re-check is queued per finding that reached `fix_applied`
  (`VulnerabilityService.SetProofOfFixQueuer` →
  `FindingActionsService.QueueProofOfFix`, the same bounded dispatch as
  `/actions/fix-applied`); this holds for every bulk fix claim. A finding it
  cannot re-check waits for a covered scan, a retest or a reviewer.
- The response lists every finding not updated with the reason
  (`{updated, skipped, failed, validations_queued, rows: [{finding_id,
  outcome, reason}]}`); the web shows them in the shared mark-fixed dialog.

## SLA status follows the status

`findings.sla_status` is recomputed on every status or deadline change, by the
trigger `trg_findings_recompute_sla_status` (migration `002181`) for every
writer, and by `Finding.UpdateSLAStatus` with the same rules
(`finding_sla_status_for`):

| Finding | `sla_status` |
|---|---|
| no deadline | `not_applicable` |
| `false_positive`, `accepted`, `duplicate` | `not_applicable` (a decision not to fix leaves the SLA) |
| `resolved` | `on_track` when closed by the deadline (met), else `exceeded` (missed): the clock stops at the verified fix; `fix_applied` keeps it running |
| open, past the deadline | `overdue` |
| open, otherwise | `on_track`, or `warning` when the escalation job set it and the deadline did not change |

The warning has **one definition**: the SLA escalation job's policy
`warning_threshold_percent` of the window from the later of
`first_detected_at` and `last_reopened_at` to the deadline (a regression's
restarted deadline is measured from the reopen). The domain no longer warns 24
hours before a deadline on its own. Migration `002181` also recomputed stale
values (closed findings left `overdue`, dispositions `exceeded`).

When the priority or the SLA policy changes, an open finding's deadline only
tightens (`min(old, now + new SLA)`) and never moves later; see
[scoring versions](scoring-versions.md#sla-on-a-priority-change).

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
- **On the finding, on every accept path.** Approving `accepted` stores the
  end in `findings.acceptance_expires_at` in the same statement as the status
  (`FindingRepository.AcceptUntil`). An approved accepted-risk or won't-fix
  suppression rule writes its `expires_at` on the findings it closes, both
  when it is approved (`applySuppressionChunk`) and when ingest links a new
  finding to it (`RecordSuppression`, same tenant only); a re-link to another
  rule takes that rule's end; an identity merge whose survivor inherits an
  acceptance inherits its end; a full-row write of an accepted finding (the
  pentest path) keeps its end. Wherever no end is given (a rule without an
  expiry, a pentest acceptance), the 90-day default
  (`vulnerability.DefaultAcceptanceDuration`) applies: an accepted risk always
  ends.
- **Cleared on leaving accepted.** The trigger
  `trg_findings_clear_acceptance_expiry` empties the column on any row that is
  not `accepted`, whatever path wrote the status, so a later accept starts
  clean.
- **Who reads it.** The CI gate honors an accepted finding only until its end
  (`cirun.honored`), even before the hourly expiry job reopens it. Threat
  models read it as the acceptance horizon.

### When an acceptance ends

The hourly `approval-expiration` controller ends every accepted finding whose
`acceptance_expires_at` has passed, whatever made it accepted (an approval, a
rule, the repair below). Each end is **one transaction**
(`FindingAcceptanceExpiryRepository.Expire`), taken only while the finding is
still accepted and its end has passed:

1. the finding returns to `confirmed` (the reopen target) and its resolution
   fields are cleared;
2. a **new SLA clock** starts at the reopen (owner decision D3): the tenant's
   policy deadline for the finding's priority from now, `sla_status`
   `on_track`; `first_detected_at` keeps the finding's true age;
3. its approved acceptance requests are marked `expired`;
4. the timeline gets an `acceptance_expired` entry (with the requests) and an
   `sla_restarted` entry (with the previous deadline).

A failure rolls all of it back and the next run retries; nothing is left with
the request expired and the finding still accepted. Approved requests whose
end passed while their finding had moved on (or holds a newer acceptance) are
only marked `expired`.

Migration `002119` filled the column for findings already accepted, from their
latest approved acceptance request or their suppression rule. Migration
`002166` gives the accepted findings that still had no end the 90-day default
from the day it runs, with a timeline note (reason `acceptance_end_default`).

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
them), and never automatically: the owner's request stays pending like any
other, and the owner approves it in a separate call to the same route with
`self_approve: true`, a reason and a fresh `totp_code` from their
authenticator app (a stolen session or password alone is not enough). The
approval is audited Critical (`exposure.disposition_self_approved`); every
refused attempt (not allowed, no reason, no code, a wrong or reused code) is
audited High (`exposure.disposition_self_approval_refused`) and changes
nothing. Without the authenticator check wired, an own approval is refused.
The pending view carries `self_approval_available` for the requester so the
web offers the call only when it can succeed. Every request, approval and rejection
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
`resolved` with what was then `resolution_method = retest_verified` (now
`fixed` / `retest`), `accepted_risk` ->
`accepted`) and `open` -> `new`, in `findings`, `pentest_findings`, approvals
and retests, then adds the CHECKs (`NOT VALID`, then `VALIDATE`). It is
idempotent. The down migration restores the old CHECK; mapped rows keep their
canonical status.
