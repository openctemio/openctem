# Finding status lifecycle

Every finding, whatever its source (scanner, import, CI, pentest), takes one
status from one set, and every write of `findings.status` follows one
lifecycle.


An organization's own labels and rules on top of these statuses (sub-statuses and lifecycle schemes) are
described in [finding-lifecycles.md](finding-lifecycles.md): they can only add constraints, never relax one
of the rules below.

## The status set

| Status | Category | Meaning |
|---|---|---|
| `new` | open | Reported, not triaged |
| `confirmed` | open | A real issue that needs a fix |
| `in_progress` | in progress | Being fixed |
| `fix_applied` | in progress | Marked fixed; a scan, a retest or a security reviewer still has to verify it |
| `resolved` | closed | Verified fixed |
| `false_positive` | closed | Not a real issue (approval) |
| `accepted` | closed | Risk accepted, with an expiry (approval) |
| `duplicate` | closed | Folded into another finding |
| `draft`, `in_review` | open, hidden | Pentest finding before publication; left out of dashboards and the Open lens |

The list is `vulnerability.AllFindingStatuses()`; the database CHECK
`chk_findings_status` (migration `001378`) and the web registry
(`web/src/features/findings/types/finding.types.ts`, labels in en and vi) hold
exactly the same values, and tests on each side pin them.

## Observation and validation: fields, not statuses

Whether the scanner still reports a finding and whether a re-check still
reproduces it are fields beside the status
([finding-status-not-observed.md](finding-status-not-observed.md)): a finding
can be in progress, stale and not reproducible at once. The statuses
`validated_fixed` and `not_observed` were retired for them (migration
`finding_status_dimensions`); the API refuses them with a 400 that names the
filter replacing them (`observation=stale`, `validation=not_reproducible`).

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
| Open | `new`, `confirmed`, `in_progress`, `fix_applied` | `vulnerability.OpenStatusSQL(col)`; in the database `is_open_finding_status(status)` |
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

The repository branch counters are kept by a database trigger on `findings`. It fires
only when a finding's `branch_id`, `severity` or `status` really changes, so a rescan
that re-sees a finding without changing them does not recount the branch.

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
  "mitigated" state closes open work (`new`/`in_progress` -> `resolved`), a VEX
  `not_affected` statement does not move it (it opens a pending false-positive
  request), an approved suppression
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

## Lifecycle version on the timeline

Every timeline entry of a status change records the version of the rules it
was decided under: `finding_activities.lifecycle_version` (and
`changes.lifecycle_version`). Today that is `platform:1`
(`vulnerability.PlatformLifecycleVersion`, the SQL function
`finding_lifecycle_version()`, pinned by a test). A BEFORE INSERT trigger
(`trg_finding_activities_lifecycle_version`, migration
`finding_activity_lifecycle_version`) sets it on every entry whose changes name
a new status, so no writer can forget it. Entries written before the column
existed stay empty.

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

Moving a finding out of an approved false positive or an accepted risk is a
reversal of a decision, so the transition engine asks for `findings:approve`
(the permission that made the decision), not only `findings:status`; the
status route and the bulk route answer 403 without it. A workflow action or a
ticket webhook is refused outright (`decided_status` block) for a false
positive, an accepted risk or a duplicate, and a workflow also for a resolved
finding: automation never undoes a person's decision.

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
  taint-source suspension, suppression re-link, the bulk verify / reject by
  filter, and the fix claim, verify and reject actions by id (one
  status-guarded batch write each, actor = the person).
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

## Side effects of a status change: one path

Every route that changes a finding's status ends in one function,
`afterStatusChange` (`internal/app/finding/status_effects.go`), with the
findings its write actually moved: the status PATCH, bulk status (and the
ticket webhooks through it), the fix claim, verify and reject actions by id
and by filter, approved requests (two-person, single-person false positive,
sole-member self-approval, group exceptions) and VEX statements. For each
moved finding it fires, once:

- the `finding_status_changed` workflow event;
- the assignee's in-app notification (not when the assignee made the move);
- a proof-of-fix re-check, for a finding that reached `fix_applied` (the
  single status PATCH now queues one too).

The outbound ticket status push of a linked finding is not fired afterwards:
it is a durable job (`durable_jobs`) the status write queues in its own
transaction, only for the findings it moved (`ticketSyncCtx` /
`TicketSyncContext` put the candidates on the context; the status writes,
approvals and VEX effects queue those that moved). A move made by a ticket
webhook is not pushed back to the ticket.

Batch writes are status-guarded and return the ids they changed
(`StatusMoveWriter.MoveStatusBatch`, `UPDATE … RETURNING id`): a finding that
changed between the read and the write is reported (`changed since it was
read`) and gets no timeline entry and no side effect, and the result counts
only the moved findings. Services outside the finding service (finding
actions, VEX) are handed `VulnerabilityService.AfterStatusMoves` at the
composition root. Reject by filter now reads its set first (at most 1000
findings, like verify by filter) so the write names the findings it moves.

Bulk assign records one `assigned` activity per finding and sends the
assignee one notification for the batch (none for a self-assignment).

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
by `POST /api/v1/findings/{id}/duplicates` (`findings:triage`; refused with 409
when exactly one side carries a false positive or risk acceptance, or the two
carry different ones), by correlation and by
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

## Transition engine

Every status change a person or a delegated actor makes is decided by one
pure function, `vulnerability.EvaluateTransition(facts, actor, to)`
(`pkg/domain/vulnerability/transition_engine.go`). The caller loads the
facts: the finding's status, source, severity, priority, KEV, whether the
actor may claim its fix, and whether its verification checklist is complete.
The engine decides:

| Target | Rule | Mode | Needs |
|---|---|---|---|
| any | an edge of `ValidStatusTransitions`; a pentest finding belongs to the pentest module | | |
| `false_positive`, `accepted` | `findings:write`; four-eyes approval | `request` | `closure_reason`, note (and the acceptance end) |
| `duplicate` | `findings:triage`; the canonical picker (`/duplicates`, `CheckMarkDuplicate`; never carries a decision across findings) | `duplicate_picker` | `duplicate_of` |
| `resolved` | `findings:verify`, from every status | `direct` | a note unless the checklist is complete |
| `fix_applied` | `findings:fix_apply`, a person, whose finding it is (assignee, assigned group, asset owner) | `direct` | a note |
| others | `findings:status`; a `findings:verify` holder may reject a fix (`fix_applied` → `in_progress`) | `direct` | |

Actors:
- **person**: a signed-in user.
- **api_key**: an organization key. The same rules apply, but it is not a person, so it cannot claim a fix.
- **workflow**: an automation `update_status` and an explicit system move. It holds no permission to verify, triage or request a disposition, and is free of the fix-claim person rules.
- **ticket_inbound**: Jira or GitHub. It moves work state only (`IsTicketInboundTarget`).
- **rule**: an approved suppression rule (the rule itself passed four-eyes). It moves the open findings the rule matches (`SuppressionApplyFromStatuses`) to the rule's disposition (`false_positive` or `accepted`) directly, with no person permission, and nothing else: any other target, a pentest finding, or a rule actor without a rule id is blocked (`rule_scope`). Approving a rule decides each matching finding through the engine with this actor and records the rule id and `actor_kind: rule` on each timeline entry. The acceptance end is still capped by priority, and the rule's scope is unchanged (the organization, or its asset).

The engine only adds constraints to the lifecycle map. `TestEvaluateTransition_NeverWiderThanTheLifecycle` proves that, for every actor and status pair, no allowed move is off the map. It also proves that no disposition is direct, no resolve lacks `findings:verify`, and no ticket closes a finding.

The paths that use the engine:
- `PATCH /findings/{id}/status` and `POST /findings/bulk/status`. Bulk refuses on the target first (`EvaluateTransitionRequest`), then refuses finding by finding.
- `/actions/fix-applied`, `/actions/verify` and `/actions/reject-fix`, plus their by-filter variants.
- Approval requests and decisions.
- Remediation group and campaign resolves (through bulk), workflow `update_status`, and the Jira and GitHub webhooks.

The same decisions are served to clients, so no client keeps a copy of the rules:
- `GET /findings/{id}/transitions` (`findings:read`) returns every move from the finding's status. Each move says whether it is allowed, its mode, the inputs it needs, and the blocked reason codes (`missing_permission` with the permission, `not_a_lifecycle_move`, `not_fix_owner`, `not_a_person`, `ticket_cannot_close`, `pentest_module`). An out-of-scope or other tenant's finding answers 404.
- `POST /findings/transitions/preview` (`findings:read`, at most 100 ids) is a dry run for a bulk change. It returns the decision per finding, and `not_found` for an id the caller cannot see. It changes nothing.
- The MCP tool `list_finding_transitions` returns the same answer as the GET route.

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
- **Resolved:** `findings:verify` (unchanged), plus evidence in proportion to
  risk (see "Evidence by risk" below). A resolve backed by a retest that
  confirmed the fix is verified by `retest`, one backed by a complete
  verification checklist by `security_review`; any other person's resolve is
  `attested` and needs a note.
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

## Evidence by risk

A person's resolve needs evidence in proportion to how risky the finding is
(`vulnerability.FindingRiskTier`, enforced by the transition engine on every
route, so the drawer, `PATCH /status`, the bulk paths, `/actions/verify` and
its by-filter form all answer the same):

| Tier | Finding | A person may resolve it with |
| --- | --- | --- |
| critical | severity critical, priority P0, or a KEV | a retest that confirmed the fix, or the verification checklist completed by someone other than the person resolving |
| high | severity high or priority P1 | the verification checklist complete, or a confirming retest |
| standard | medium, low, info | a note (attested) |

- A blocked move is reported by `GET /findings/{id}/transitions` and the bulk
  preview with the code `evidence_required` (critical) or
  `checklist_required` (high), so the web disables it with the reason instead
  of failing on submit. `PATCH /status` answers 400 with the same reason.
- Evidence must be newer than the finding's last reopen and its last
  sighting (`GREATEST(last_reopened_at, last_seen_at)`): a retest or a
  checklist completed before a regression, or before a scan saw the finding
  again, no longer counts, so a critical finding that came back is not closed
  by one person on the proof of the previous fix.
- A covered scan that no longer sees the finding, and a retest with
  `retest.auto_resolve`, close it without a person and are not affected.
- The by-filter verify evaluates each matching finding (up to 1000 per call)
  and resolves only those whose evidence is in place; the response counts
  what moved.

## Risk acceptance end

An accepted risk always ends; a false positive does not (it is re-reviewed
instead).

- **Capped by priority.** The longest a risk may stay accepted is P0 or KEV
  30 days, P1 90, P2 180, P3 (and unclassified) 365
  (`vulnerability.MaxAcceptanceFor`). A request that names no end gets 90
  days, or the cap when it is shorter; a request whose end is past the cap is
  refused with the limit, never shortened silently. Approving a request whose
  end is past the finding's current cap (its priority rose since) is refused
  too; the requester asks again with a shorter end. The finding response
  carries `max_acceptance_days`, and the approval dialog limits its date
  picker to it.
- **Suppression rules too.** An accepted-risk rule keeps its own end (at
  most a year), but each finding it accepts, on approval, on a re-link or
  when ingest links a new finding, ends at the rule's end or the cap of that
  finding's priority, whichever is sooner (`acceptanceCappedSQL`, using
  `finding_max_acceptance_days`).
- **Existing acceptances over the cap are flagged, not cut.** Migration
  `002541_acceptance_cap_review` opens a decision review
  (`acceptance_exceeds_cap`) with a timeline entry for every accepted finding
  whose end is past its cap, and reports the count (`NOTICE`). The end is not
  changed; a person decides. `002542_acceptance_cap_review_validate`
  validates the widened review-reason constraint.
- **One value, one meaning.** `finding_status_approvals.expires_at` is the end
  of the decision the request asks for. A request for `accepted` gets 90 days
  when it names no end and is refused with an end in the past or more than a
  year ahead; a request for `false_positive` is refused when it names an end.
  Once the requested end has passed the request can no longer be approved (it
  would accept nothing). Approving an older `accepted` request that has no end
  gives it the 90-day default from the approval.
- **Decide-by, separate from the end.** Every request also has
  `finding_status_approvals.decide_by` (14 days after it was made,
  `vulnerability.DefaultDecisionWindow`). A pending request past it cannot be
  approved or rejected, and the hourly `approval-expiration` controller marks
  it `expired` with a timeline entry (`reason: decision_overdue`) and an audit
  row (`finding_approval.expired`) in its tenant
  (`FindingApprovalRepository.ExpireOverdueRequests`). A new request can then
  be made.
- **One pending request per finding.** The unique partial index
  `ux_finding_status_approvals_pending` allows one pending request per
  finding, from a person or a platform actor; a second one answers 409. An
  identity merge whose two findings both wait for a decision keeps the
  survivor's request and cancels the other (`settleLoserPendingApproval`).
- **Approve is one transaction.** The request row (claimed with its version
  while still pending), the finding's status and acceptance end, and the
  `approval_approved` timeline entry commit together
  (`FindingApprovalRepository.ApproveAndApply`). Of two approvers deciding at
  once only one applies it (the other gets 409); a finding that moved in
  between rolls everything back and the request stays pending. A request is
  for a finding inside the requester's data scope (404 otherwise).
- **Audit.** Every request, approval, rejection and cancellation writes an
  audit row (`finding_approval.requested|approved|rejected|canceled`, resource
  type `finding_approval`, metadata: finding, requested status, acceptance end,
  decide-by; never the justification text). A refused attempt to approve one's
  own request is recorded as `finding_approval.self_approval_refused` (denied,
  medium), so the attempts can be reviewed.
- **Who is told.** A new request (a person's or an AI triage proposal)
  notifies the members who may decide it, in-app (`finding_approval`) and by
  email: owners, admins and roles holding `findings:approve`
  (`ScopeActorRepository.FindingApprovers`), filtered to those whose data scope
  holds the finding (`datascope.AssertFindingForUser`), never the requester
  (`internal/app/finding/approval_notify.go`). The email carries the finding
  title, requested status and dates, never the justification; the link opens
  the inbox, sign-in required. `POST /api/v1/approvals/{id}/remind`
  (`findings:write`) repeats it at most once an hour per request
  (`reminded_at`, atomic), audited `finding_approval.reminded`. Requests VEX
  statements make are announced from the requests table as an outbox: the
  `vex-request-notice` job (every minute) claims rows with no
  `approvers_notified_at` (`FOR UPDATE SKIP LOCKED`) and sends one notice and
  one email per tenant and approver, counting only findings in that
  approver's data scope and naming at most five titles; without a data-scope
  check nobody is told (`DispatchVEXRequestNotices`, `NotifyVEXRequests`).
- **Sole member.** An organization with one person has nobody to ask. Its
  owner may approve their own pending request
  (`POST /api/v1/approvals/{id}/self-approve`, `findings:approve`) only while
  the organization has exactly one active person (an active, unexpired
  membership of an active `person` account; checked in the database at
  decision time, `ScopeActorRepository.IsSoleActiveOwner`) and no member was
  suspended, offboarded, deleted, expired or demoted, and no role changed, in
  the last 7 days (`recentApproverChange`, memberships and audit log), with a fresh
  authenticator code (`VerifyFreshTOTP`, single use) and a reason. An accepted
  risk then ends within `vulnerability.SoloAcceptanceLimit` (7 days for P0 or
  KEV, 45 for P1, 90 otherwise). The request carries `self_approved` and the
  reason; the audit row is `finding_approval.self_approved` (high); every
  refusal is `finding_approval.self_approval_refused`; the organization's
  channels get a security alert and the backup contact
  (`settings.finding_approvals.backup_contact_email`) is emailed
  (`internal/app/finding/approval_solo.go`). The settings route
  (`/api/v1/organization/settings/finding-approvals`) needs `settings:write`
  and a recent re-authentication; changes are audited with before/after and
  the approvers are told.

- **Daily digest.** The hourly `approval-digest` controller sends each
  approver, at most once per 23 hours and organization
  (`finding_approval_digest_sent`), one in-app notice
  (`finding_approval_digest`) and one email: the requests they may decide
  (never their own, the finding in their data scope), how many expire within
  two days, and up to five titles they can see
  (`internal/app/finding/approval_digest.go`). Muting the digest type in the
  notification preferences opts out of both.

### Approval policy

Every false-positive and accepted-risk request is evaluated by the approval
policy (`pkg/domain/approvalpolicy`, design: RFC-111) from facts read on the
server, when it is made and again when someone approves it
(`internal/app/finding/approval_policy.go`):

- **Risk class:** critical (severity critical, P0, KEV), high (severity high,
  P1, a validated exploit, EPSS at or above the threshold, 0.5 unless the
  organization lowers it), standard. An acceptance on a crown-jewel or
  internet-exposed asset is one class higher.
- **Tier:** `single` (the requester alone), `peer` (one other person),
  `security` (one other person from the security pool, recent
  re-authentication), `dual` (two other people, one from the security pool,
  each re-authenticated). Defaults: false positive by the level below;
  accepted risk `peer` / `security` / `dual` for standard / high / critical.
  Floors that no policy lowers: an accepted risk never below `peer`, and
  never below `security` from high up.
- **Who may approve:** members holding `findings:approve` with the finding
  in their data scope, except the requester and **the owners of the finding's
  asset** (user owners and members of owner groups, ownership primary or
  secondary), and the assignee when the organization asks. A requester who
  owns the asset never decides a false positive alone. The security pool is
  the organization's `security_pool_group_id` group; when nobody in it is
  eligible the approver pool stands in (`security_pool_fallback`, recorded
  on the sign-off) unless `security_pool_strict`.
- **Sign-offs:** each approval is a row in `approval_signoffs` (one per
  person). `POST /approvals/{id}/approve` locks the request, judges the
  signer against the sign-offs already in, records the sign-off and, on the
  last one, applies the request with its timeline entry in the same
  transaction (`FindingApprovalRepository.SignOff`). Earlier sign-offs count
  only while their signer still qualifies. A partial sign-off answers 200
  with the request still `pending` and `approvals_collected` /
  `approvals_required`; it is on the timeline as `approval_signed` and in the
  audit log as `finding_approval.signed`. Refusals answer 403
  `APPROVER_NOT_ELIGIBLE` with `details.reason` (`asset_owner`, `assignee`,
  `not_in_security_pool`, `already_signed`, `not_an_approver`), 409
  `NO_ELIGIBLE_APPROVER` when the organization cannot complete the request,
  or 403 `STEP_UP_REQUIRED`; each is audited
  `finding_approval.approval_refused`.
- **Ends and deadlines:** the acceptance cap is the platform's (P0/KEV 30,
  P1 90, P2 180, P3 365 days) or the organization's class cap when shorter;
  the decision deadline is 14 days or the organization's shorter value. A
  `security` or `dual` request carries a note of at least 20 characters.
- **Stored on the request:** `tier`, `risk_class`, `required_approvals`,
  `policy_eval` (the evaluation, as evidence) and, when decided,
  `decision_facts` (the facts it was decided on).
- **The organization's policy** is `settings.finding_approvals.policy`
  (`GET/PUT /api/v1/organization/settings/finding-approvals/`, same gate as
  the rest of the section: `settings:write`, an owner or administrator, recent
  re-authentication; audited with before and after; approvers told). It only
  adds: tier cells per `<kind>.<class>` (never below the floor), security
  pool and strict mode, exclude assignee, step-up for every tier, class caps,
  decision deadline, EPSS threshold, material-change behavior. A change that
  only tightens applies at once; a change that relaxes anything is
  `pending_policy` until `pending_policy_at` (24 hours) while the stricter of
  both applies field by field. The response carries the platform `floors` and
  `defaults`.
- `GET /api/v1/findings/{id}/approvals/policy?status=accepted|false_positive`
  answers the evaluation for the caller as requester (tier, reasons,
  approvers, step-up, cap, deadline, `satisfiable`).

### Material change of standing decisions

A decision is valid for the facts it was made on. The approval row keeps
`decision_facts` (when decided) and `facts_baseline` (the facts last checked).
The `approval-material-change` controller (every 10 minutes, 200 per run,
`internal/infra/controller/approval_material_change.go`,
`internal/infra/postgres/finding_material_change.go`) takes the latest
approved request of each accepted finding, and of each false positive one
person decided (`single_person` or the sole member's), whose finding moved up
since the baseline: severity or priority up, KEV added, EPSS higher, an
exploit newly validated, the asset newly internet exposed or a crown jewel.
For each, under the organization's policy (`approvalpolicy.MaterialChange`):

| Decision | Floor | `on_material_change` option |
|---|---|---|
| accepted risk | **ends** when the tier the finding needs now is above the decided tier, or its cap now ends before the decided end; otherwise a review flag `material_change_accepted` (the decision stands) | `end_on_any_change`: any signal ends it |
| one-person false positive | review flag `material_change_single_person` | `revoke`: withdrawn, the finding is `confirmed` again |

- **Ending** is the expiry path (above) with reason `material_change` and the
  signals: `confirmed`, a new SLA clock, the request `expired`, the timeline
  entry `acceptance_expired`, in one transaction.
- **Withdrawing** writes the status with a platform transition (timeline
  `status_changed`, reason `material_change`), a new SLA clock, the request
  `expired`.
- Every action is audited (`finding_approval.material_change_ended`,
  `..._flagged`, `..._revoked`) and the requester and the approvers of the
  decision get an in-app notification (title and the change, no
  justification).
- An EPSS rise that stays below the threshold only moves the baseline. A
  decision made before the baseline existed gets today's facts on the first
  run and no action.
- The triggers of the single-person flag (severity, KEV, new evidence, above)
  stay; the controller adds the other signals and the `revoke` option.

### False-positive approval level

`settings.finding_approvals.fp_approval` decides who decides a false positive
(`internal/app/finding/approval_fp_policy.go`):

| Level | A second person is needed for |
|---|---|
| `all` (default) | every false positive |
| `high_and_above` | a material finding: critical or high, KEV, P0/P1, a validated exploit (`validation_outcome = reproducible`), a crown-jewel or internet-exposed asset (`vulnerability.FPFacts.Material`) |
| `off` | none |

An accepted risk always needs a second person. When the level lets one person
decide (and the approval policy gives the request the `single` tier: the
requester holds `findings:approve`, has the finding in their data scope and
does not own its asset), the false positive is applied at once: the request row is
written approved with `single_person`, the status, closure reason and timeline
entry in one transaction (`FindingApprovalRepository.CreateApplied`), audited
`finding_approval.single_person_decided`. A member without `findings:approve`
still files a pending request. Safeguards: a later severity rise, KEV listing
or new evidence on a false positive one person decided raises the
`material_change_single_person` review flag (triggers
`trg_findings_single_person_fp_review`, `trg_finding_evidence_single_person_fp_review`,
function `flag_single_person_fp_review`); `second_look_percent` (0-10) flags a
random share (`second_look_sample`, crypto/rand). Changing the level needs
`settings:write` and a recent re-authentication, is audited with before/after
and the approvers are told; a lower level takes effect 24 hours later
(`pending_fp_approval_at`), a higher one at once.
`GET /api/v1/findings/{id}/approvals/policy` tells the request dialog how a
false positive on that finding is decided now. Not built yet: a digest of
single-person decisions (they are in the audit log and the approvals list).
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
approval. For an item whose **highest severity ever** was high or critical it
takes two people (`exposure_events.peak_severity` only goes up, so a re-ingest
that reports the same exposure as low does not lift the rule):

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
nothing. Own approval is also refused for 7 days after any member of the
organization was suspended, offboarded or removed, or a membership expired
(read from `tenant_members` and the tenant's audit log): removing the only
other approver must not open the path at once. The refusal says from when it
is possible again. Without the authenticator check wired, an own approval is refused.
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
