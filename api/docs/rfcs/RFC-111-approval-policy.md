# RFC-111: Approval policy (one evaluator for false positives, accepted risks, suppressions and group exceptions)

| | |
|---|---|
| Status | Accepted (2026-10-16). Being implemented in small PRs; §13 lists their state |
| Scope | api (pure evaluator, finding approvals, suppression rules, remediation task exceptions, material-change controller, settings API), web (Settings → Findings → Approvals, request dialog, approvals inbox, task exception dialog) |
| Related | the finding status lifecycle and its approvals (`docs/architecture/finding-status-lifecycle.md`), RFC-098 (remediation tasks), RFC-110 (tenant lifecycles), step-up re-authentication (`docs/architecture/step-up-reauth.md`) |

## 1. Summary

A false positive, an accepted risk, a suppression rule and an exception on a remediation task all hide a
risk. Today each path has its own rule: a false positive follows the organization's level (`all`,
`high_and_above`, `off`), an accepted risk always needs one other approver whatever the finding, a
suppression rule needs one other approver, and a remediation task has no exception at all. A critical,
known-exploited finding accepted on an internet-facing asset needs the same single approver as a low
finding on a test host, and nothing ends the acceptance when the finding turns worse.

**Decision.** One pure evaluator (`pkg/domain/approvalpolicy`) decides, for every such request, from facts
read on the server:

1. **the tier**: who may decide and how many people (§3);
2. **who may approve**: the approver pool, the security pool, and who is excluded (§4);
3. **how long**: the decision deadline and the longest end (§5);
4. **what a later change does**: end, flag or revoke (§6).

The platform sets **floors**. The organization's policy can only **add** constraints above them; the
platform default sits above the floor in one place (a critical acceptance needs two approvers) and an
organization may relax that default down to the floor, 24 hours after the change. Four-eyes on an
accepted risk is a floor: it can never be turned off. Every path (the finding drawer, `PATCH /status`,
bulk status, the approvals inbox, a Jira status, a VEX statement, AI triage, a suppression rule, a task
exception) goes through the same evaluator.

## 2. Inputs

The service reads the facts in the database at request time and again at decision time; the client sends
none of them.

| Fact | Source |
|---|---|
| severity, priority class, KEV | `findings.severity`, `findings.priority_class`, `findings.is_in_kev` |
| EPSS | `findings.epss_score` |
| validated exploit | `findings.validation_outcome = 'reproducible'` |
| crown jewel, internet exposed | `assets.is_crown_jewel`, `assets.is_internet_accessible` of the finding's asset |
| asset owners | `asset_owners` of the finding's asset: user owners, and members of owner groups, with ownership `primary` or `secondary` |
| assignee | `findings.assigned_to` |
| approvers | members who hold the approve permission of the request kind and have the finding in their data scope |

**Risk class** (one function, used by every kind):

| Class | When |
|---|---|
| `critical` | severity critical, priority P0, or KEV |
| `high` | severity high, priority P1, a validated exploit, or EPSS at or above the threshold (platform 0.5; an organization may lower it) |
| `standard` | anything else |

For an accepted risk (a request or a rule), a crown-jewel or internet-exposed asset raises the class by
one step (standard to high, high to critical): accepting a risk where it is reachable or where it matters
most needs more than accepting it elsewhere.

## 3. Tiers

| Tier | Who decides | Step-up of the approver |
|---|---|---|
| `single` | the requester alone, when they hold the approve permission and the finding is in their data scope | none |
| `peer` | one other person from the approver pool | none (an organization may require it) |
| `security` | one other person from the security pool (§4) | recent re-authentication (10 minutes) |
| `dual` | two other people, distinct, at least one from the security pool | recent re-authentication, each |

The **sole member** of an organization (exactly one active person) keeps the existing own-approval path
(fresh authenticator code, reason, halved acceptance caps, alerts). It is the only way a person approves
their own request, and it is not a tier: it is refused while a second eligible person exists.

### 3.1 Floors and defaults

Kinds: `false_positive` and `accepted` (finding requests), `rule_false_positive` and `rule_accepted`
(suppression rules; `wont_fix` rules count as `rule_accepted`). A task exception is evaluated per member
with the finding kinds (§7).

| Kind | standard | high | critical |
|---|---|---|---|
| `false_positive` | floor `single` · default `peer` | floor `single` · default `peer` | floor `single` · default `peer` |
| `accepted` | floor **`peer`** · default `peer` | floor **`security`** · default `security` | floor **`security`** · default `dual` |
| `rule_false_positive` | floor **`peer`** · default `peer` | floor **`peer`** · default `security` | floor **`peer`** · default `security` |
| `rule_accepted` | floor **`peer`** · default `peer` | floor **`security`** · default `security` | floor **`security`** · default `dual` |
| task exception | the highest member tier, never below **`peer`** | | |

- The false-positive floor is `single` because the organization's false-positive level may be `off`
  (owner decision, 2026-10-15). The level is part of the policy: `all` gives `peer`, `high_and_above`
  gives `single` for a non-material finding, `off` gives `single`. A tier set for a false-positive class
  raises that further.
- A rule or a task exception decides many findings, including future ones for a rule: never `single`.
- `single` is never available to a requester who owns the finding's asset (§4).

### 3.2 The organization's policy

Stored in the tenant settings section `finding_approvals.policy`. Every field can only make the result
stricter than the floor:

| Field | Meaning | Bound |
|---|---|---|
| `tiers` | a tier per `<kind>.<class>` (`accepted.high: dual`) | never below the floor |
| `security_pool_group_id` | the group that forms the security pool | a group of the organization |
| `security_pool_strict` | no fallback to all approvers when the pool has nobody eligible | |
| `exclude_assignee` | the finding's assignee may not approve | |
| `step_up_all_tiers` | the `peer` approver re-authenticates too | |
| `max_acceptance_days` | per class: `standard`, `high`, `critical` | at most the platform cap (P0/KEV 30, P1 90, P2 180, P3 365 days) |
| `decide_within_days` | how long a pending request waits for a decision | 1 to 14 days |
| `epss_threshold` | the EPSS score from which a finding is `high` | 0.01 to 0.5 |
| `on_material_change.accepted` | `end_on_tier_rise` (floor) or `end_on_any_change` | |
| `on_material_change.single_person_fp` | `flag` (floor) or `revoke` | |

**Changing the policy** needs `settings:write`, an owner or administrator, and a recent
re-authentication; it is audited with the values before and after, and every approver is told. A change
that only tightens applies at once. A change that relaxes anything is stored as `pending_policy` and takes
effect 24 hours later; until then the stricter of the two policies applies field by field (so the
tightening part of a mixed change applies at once). Choosing another security pool group counts as a
relaxation.

## 4. Who may approve

- **Approver pool.** Members with an active account and membership who hold the kind's approve permission
  (`findings:approve`; `findings:suppressions:approve` for rules) and have the finding in their data scope.
  Integration principals, API keys and actors (AI triage, VEX, Jira) are never approvers.
- **Security pool.** The members of `security_pool_group_id` within the approver pool. When the
  organization has none, or nobody in it is eligible after the exclusions, the request falls back to the
  approver pool; the decision records `pool_fallback` and the inbox says so. `security_pool_strict` turns
  the fallback off. A person counts as a pool member only 24 hours after joining the group (the pool is
  read live when someone signs, so an account added a moment ago must not sign as the pool), and adding or
  removing a member of the pool group, or deleting it, needs a recent re-authentication.
- **Excluded (floor):** the requester (except the sole member); the owners of the finding's asset (user
  owners, and members of owner groups, ownership `primary` or `secondary`): a person never approves the
  hiding of a risk on an asset they own. For a rule bound to an asset, that asset's owners; for a task
  exception, the owners of every member's asset.
- **Excluded (organization):** the finding's assignee (`exclude_assignee`).
- **Two approvers.** Each signs off separately; the request applies when the last required sign-off is
  in, in the same transaction as the status change. A person signs once. The last sign-off must come from
  the security pool when none of the earlier ones did. Sign-offs collected before the facts changed count
  only if the signer still qualifies for the tier computed now.
- **Requests made by an actor** (AI triage, VEX, a linked ticket) have no person behind them, and the
  account that moved a ticket is not known as a member, so they need one sign-off more than the tier asks
  (peer: two, dual: three). A ticket's proposed end is within the organization's cap for the finding.
- **Nobody eligible.** The evaluator says so (`no_eligible_approver`, with the reason) and the request
  stays pending; nothing approves on a timeout.

## 5. Ends and deadlines

- **Accepted risk:** the end is required; the default is 90 days or the cap when shorter; the cap is the
  platform's (by priority and KEV) or the organization's class cap, whichever is shorter. An end past the
  cap is refused, never shortened silently (a task exception shows each member's end in its preview, §7).
- **Decision deadline:** 14 days (or the organization's shorter value) from the request; the hourly job
  expires overdue requests.
- **Suppression rules:** at most 365 days; an accepted-risk or won't-fix rule ends no later than the class
  cap of the worst finding it matches when approved.

## 6. Material change

A decision is valid for the facts it was made on. When an accepted risk is approved, or a false positive
is decided by one person, the approval row stores the facts (`decision_facts`) and a moving baseline
(`facts_baseline`). A controller (every 10 minutes, bounded batches, one transaction per finding)
compares the baseline with the facts now.

**Signals:** `severity_raised`, `priority_raised`, `kev_added`, `epss_crossed` (the score reached the
threshold), `exploit_validated`, `exposure_raised` (the asset became internet-exposed or a crown jewel).

| Decision | Floor | Organization option |
|---|---|---|
| accepted risk | **ends** when the tier computed now is above the decided tier, or the cap now ends before the decided end; any other signal raises a review flag (`material_change_accepted`) | `end_on_any_change`: any signal ends it |
| false positive decided by one person (`single_person` or the sole member's) | review flag (`material_change_single_person`) | `revoke`: the false positive is withdrawn and the finding is open again |

- **Ending** an acceptance is the expiry path with another reason: the finding returns to `confirmed`, a
  new SLA clock starts, the approved request is marked `expired`, and the timeline gets
  `acceptance_ended_material_change` with the signals.
- **Telling people:** the requester and the approvers of the decision get an in-app notification; the
  audit log gets `finding_approval.material_change_ended`, `..._flagged` or `..._revoked`.
- A decision made before this controller existed gets the facts at first sight as its baseline and no
  action.
- A pending request is evaluated again at decision time (§4).

## 7. Group-level exception on a remediation task

"No maintenance window until 1 December" is one decision about many findings.

- `POST /api/v1/remediation/tasks/{task_id}/exception/preview` and `POST .../exception`, body
  `{requested_status: accepted | false_positive, closure_reason, justification, expires_at}`; route
  `remediation:write` and `findings:write`; every member must be in the caller's data scope (the task rule
  for restricted members); at most 500 open members (the bulk ceiling).
- It creates one `approval_batches` row and one pending finding request per open primary member, linked by
  `batch_id`. Members that cannot make the move, or already have a pending request, are listed as skipped.
- **Tier:** the highest member tier, never below `peer`; the exclusions are the union over members.
- **Per-member caps:** each member's end is the earlier of the requested end and that member's cap; the
  preview lists every member with its tier and end.
- **One decision:** `POST /api/v1/approvals/batches/{id}/approve | reject | cancel`. Sign-offs are on the
  batch. The last sign-off applies every member in one transaction; a member that moved since is canceled
  with the reason and listed. A member request of a batch cannot be decided alone.
- Afterwards each member is an ordinary decision: its own end, expiry and material-change check.
- Findings that join the task later are not covered.

## 8. Reason codes

A request always carries a structured code and a note:

- finding requests and task exceptions: the closure reason (false positive: the VEX justifications,
  `detection_error`, `test_or_example_code`; accepted: `risk_accepted`, `compensating_control`,
  `no_fix_available`, `wont_fix`);
- suppression rules: `reason_code` from the same catalog for the rule's type (new, required);
- the note is required; for `security` and `dual` it is at least 20 characters.

## 9. API

| Route | Change |
|---|---|
| `GET /api/v1/findings/{id}/approvals/policy?status=` | adds the evaluation: tier, class, required approvals, reasons, security pool and fallback, step-up, longest end, decision deadline, eligible approver count, whether the caller may decide |
| `POST /api/v1/findings/{id}/approvals` | evaluated; the request stores tier, class and required approvals |
| `POST /api/v1/approvals/{id}/approve` | a sign-off; answers 200 with `approvals_collected` / `approvals_required`; applies on the last one |
| `GET /api/v1/approvals` | each request carries tier, required and collected approvals, and `batch_id` |
| `GET, PUT /api/v1/organization/settings/finding-approvals/` | `policy`, `pending_policy`, `pending_policy_at`, and the floors and defaults for the editor; `PUT` with `cancel_pending: true` drops every waiting lowering (level, second look, policy) and keeps the values in force |
| `POST /api/v1/suppressions/rules` | `reason_code` required; approval evaluated |
| task exception routes | §7 |

Refusals carry stable codes: `APPROVER_NOT_ELIGIBLE` (with `excluded_reason`: `requester`, `asset_owner`,
`assignee`, `not_in_security_pool`, `already_signed`), `STEP_UP_REQUIRED`, `NO_ELIGIBLE_APPROVER`,
`BATCH_MEMBER`.

## 10. Data model

- `finding_status_approvals`: `tier`, `risk_class`, `required_approvals`, `policy_eval` (at request),
  `decision_facts`, `facts_baseline`, `batch_id`.
- `approval_signoffs`: `tenant_id`, `subject_type` (`finding_approval`, `approval_batch`,
  `suppression_rule`), `subject_id`, `user_id`, `security_pool`, `pool_fallback`, `step_up`, `created_at`;
  unique per subject and user.
- `approval_batches`: the group exception request (§7).
- `suppression_rules`: `reason_code`, `tier`, `required_approvals`.
- `finding_decision_reviews.reason`: adds `material_change_accepted`.

Migrations add nullable columns and new tables; CHECK and foreign key constraints are added `NOT VALID`
and validated in a separate migration, so no step holds a long lock on a populated table.

## 11. Threat model

| # | Threat | Control | Test |
|---|---|---|---|
| T1 | A stolen approver session approves a critical acceptance | `security`/`dual` need recent re-authentication; `dual` needs a second person | refused without step-up |
| T2 | The asset owner hides a risk on their own asset | asset owners excluded at every tier, `single` included | owner as approver refused, owner single-person FP falls back to a request |
| T3 | Bypass through another path (bulk status, `PATCH /status`, Jira, VEX, AI, a rule, a task exception) | the transition engine refuses direct moves; every request path evaluates; actors only request | one negative per path |
| T4 | A relaxed policy used in the same sitting | relaxations wait 24 hours; the stricter policy applies meanwhile; audited; approvers told | pending policy not in force before its time |
| T5 | A tenant policy below the floor (API call, a bug in the editor) | the evaluator clamps to the floor; the settings validator refuses | property test over random policies: result ≥ floor |
| T6 | Two approvers racing, or one person signing twice | sign-offs unique per person; the last sign-off locks the request row | concurrent sign-off test |
| T7 | A decision outliving the facts | material-change controller ends or flags | controller tests per signal |
| T8 | A group exception smuggling a critical finding | the batch takes the highest member tier and per-member caps | mixed-batch test |
| T9 | Cross-tenant or out-of-scope approval | every read and write is by `(tenant_id, id)`; the pool is per tenant and data scope; the security pool group must be the tenant's | two-tenant negatives |
| T11 | The person who moved a ticket approving the request their ticket made, or an accomplice added to the security pool in the same sitting | actor requests need one extra sign-off; pool members count after 24 hours; edits of the pool group need step-up | actor sign-off, fresh pool member and pool edit tests |
| T10 | Request text used to steer the approver | the note is untrusted plain text; the code is from a closed list | |

## 12. UI

- **Settings → Findings → Approvals:** the floor and default per kind and class as a grid; the tenant's
  value per cell (only stricter choices offered); the security pool group, the exclusions, caps, deadline,
  EPSS threshold and material-change behavior; a pending relaxation banner with its time; step-up on save.
- **Request dialog:** the tier and why ("needs 2 approvers: critical, KEV"), who may approve (count and
  pool), the longest end, the reason code and note.
- **Inbox:** tier, collected/required approvals, a disabled Approve with the reason for an ineligible
  caller, group exceptions as one row.
- **Remediation task:** "Request exception" with the preview (members, tiers, ends).
- Every string in en and vi.

## 13. Delivery

| Step | Content | State |
|---|---|---|
| 1 | This RFC | merged (#2401) |
| 2 | Pure evaluator with floors, defaults, tenant policy, risk class, exclusions, sign-off rule, material-change decision; policy matrix and property tests | in review (#2404) |
| 3 | Finding requests and approvals use the evaluator: tiers, security pool, asset-owner exclusion, two approvers (sign-offs), step-up, caps; settings API for the policy | in review (#2411) |
| 4 | Suppression rules: reason code, evaluated tier, sign-offs | in review (#2416) |
| 5 | Material-change controller | in review (#2419) |
| 6 | Group exception on remediation tasks | in review (#2422) |
| 7 | Web: approvals settings, request dialog, inbox (#2421); task exception dialog and group exceptions in the inbox | in review / in progress |

Follow-ups: the approvals list does not yet say whether the viewer may decide a request (the web shows the
reason only after Approve); an exception rule that covers future findings above its approved tier (§3.1,
rules) is evaluated at approval only.

## 14. Not in scope

Break-glass, delegation and escalation, chat approvals, an AI pre-check, fatigue signals, the exceptions
register export, and moving exposure dispositions and scope or scan approvals onto the evaluator. Each can
reuse the evaluator later.
