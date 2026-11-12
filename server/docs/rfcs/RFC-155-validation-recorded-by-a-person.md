# RFC-155: Validation recorded by a person

| | |
|---|---|
| Status | Accepted (2026-11-12): design only, nothing built. Decisions D1 and D2 adopted for the owner; open questions in §15 |
| Scope | api (validation evidence store, finding priority classification, approval policy kinds, material-change controller, a new expiry controller, finding routes), web (finding Validation tab, approvals queue) |
| Architecture | [validation-engine.md](../architecture/validation-engine.md), [priority-explainability.md](../architecture/priority-explainability.md), [finding-severity-override.md](../architecture/finding-severity-override.md), [finding-evidence.md](../architecture/finding-evidence.md) |
| Related | RFC-011 (validation dispatch), RFC-011.2 (confirm-or-downgrade loop), RFC-111 (approval policy), RFC-153 (exploration), RFC-156 (cycle close, comparison and report) |

## 1. Problem

The Validation stage of a CTEM cycle asks whether an exposure can actually be
used against this organization. Today only machines answer: a template
re-check, an emulation run or a retest sets a finding's validation outcome.
A security person who proves by hand that a finding is exploitable, or that a
control stops it here, has nowhere to record it with an effect. They can
attach a note, but the note changes nothing: priority stays where the
scanners put it, and the cycle cannot report how many findings validation
raised or lowered.

Two different "downgrades" must stay apart:

- **Not reproducible** (RFC-011.2): a re-check no longer observes the
  condition. It is close to "fixed".
- **Not exploitable here** (this RFC): the condition is present, but a person
  proved it cannot be used in this environment, because a control prevents it
  or a precondition is absent.

This RFC adds the second meaning as its own outcome. It never overloads the
first.

## 2. Today (checked on develop, 2026-11-12)

Paths are relative to `server/`.

- **One store of validation results.** `validation_evidence`
  (`migrations/001146_baseline.up.sql:9644`) holds tenant_id, finding_id,
  simulation_run_id, executor_kind (free text, no CHECK), technique, outcome
  (`detected`, `not_detected`, `inconclusive`, `error`, `skipped`), summary,
  evidence jsonb, detection_status and detection_detail. It has no foreign
  key to `findings`; the index `idx_validation_evidence_finding (tenant_id,
  finding_id, created_at DESC)` exists. Writers: the source-authenticated
  ingest `POST /api/v1/validation/evidence` and the simulation service
  (`internal/infra/postgres/validation_evidence_repository.go:28`,
  `internal/app/compliance/simulation.go`). Readers: the finding's Validation
  list `GET /api/v1/findings/{id}/evidence/` (`findings:read`,
  `internal/infra/http/routes/validation.go:44-56`), validation coverage and
  the downgrade figure.
- **Manual notes are not validation results.** `POST
  /api/v1/findings/{id}/evidence/` (`findings:write`) uploads a note through
  the attachment store (`internal/app/finding/evidence.go:120`). Typed
  request and response evidence with masking, encrypted secrets and an
  audited reveal lives in `finding_evidence` with origin `manual`
  (`pkg/domain/evidence/record.go:28-37`, `internal/app/evidence/service.go:93-143`,
  reveal `POST /api/v1/findings/{id}/evidence-items/{item}/reveal` with
  `findings:evidence:reveal` and a recent sign-in).
- **The finding outcome.** `findings.validation_outcome` takes `reproducible`
  or `not_reproducible` (CHECK `chk_findings_validation_outcome`, baseline
  line 5398). Only template, emulation-kit and retest results set it
  (`internal/app/validation/verdict.go:65-82`,
  `internal/infra/postgres/finding_retest_repository.go:288`).
  `reproducible` sets `ValidatedExploitable`
  (`internal/app/finding/priority_classification.go:867`), which the
  exploitation floor lifts to at least P1
  (`pkg/domain/vulnerability/priority.go:204-232`). The priority trigger
  already watches `validation_outcome`
  (`migrations/003101_priority_queue_validation_trigger.up.sql`).
- **One lowering step exists, for controls.** `applyControlReduction`
  (`pkg/domain/vulnerability/priority.go:342-370`) lowers the class by one
  level when an effective compensating control covers the asset, never takes
  a KEV finding below P1, and writes the step into the reason. Nothing lowers
  a class on a validation result.
- **Lowering moves wait for approval.** A severity downgrade that the
  organization's policy does not let one person decide waits in
  `finding_severity_requests` with its tier, required approvals and decide-by
  time; each sign-off is a row in `approval_signoffs` (subject_type
  `severity_request`) (`migrations/002965_finding_severity_override.up.sql`).
  Its routes are `POST /api/v1/findings/{id}/severity-requests/{rid}/approve`
  (`findings:approve`, step-up sensitive), `/reject` and `/cancel`
  (`internal/infra/http/routes/exposure.go:360-366`). Tiers, classes, floors
  and defaults are in `pkg/domain/approvalpolicy/tier.go`; kinds today are
  `false_positive`, `accepted`, `rule_false_positive`, `rule_accepted`
  (`tier.go:158-172`). There is no priority-lowering kind.
- **Deadlines only tighten.** The SLA applier never moves a deadline later
  (`internal/app/sla/applier.go:111-135`). The one explicit extension,
  `RelaxForDecision` (`applier.go:233-242`), is called only by an approved
  severity downgrade (`internal/app/finding/severity_override.go:229`).
- **Material change.** A controller re-checks standing decisions every few
  minutes and ends, flags or withdraws them when the finding's facts move up
  (`internal/infra/controller/approval_material_change.go`,
  `pkg/domain/approvalpolicy/facts.go:197-230`: severity or priority up, KEV
  added, EPSS crossing the threshold, a newly validated exploit, the asset
  newly internet exposed or a crown jewel).
- **Permissions.** `findings:verify` is the "security person confirms state"
  permission (`pkg/domain/permission/permission.go:100`); `findings:approve`
  decides approvals (`permission.go:98`).

## 3. Decisions

D1 and D2 were adopted on 2026-11-12 on the owner's behalf from the plan's
recommendation. The rule text below is what tests assert.

**R1. The record.** A person with `findings:verify` and the finding's asset in
their data scope records a validation result on one finding: method,
exploitable (`yes`, `no`, `inconclusive`), how the control behaved, the
environment, when the test was done, a summary, optionally a compensating
control it relied on and up to 5 evidence items. Every record is kept, also
after it expires, is rejected or is withdrawn.

**R2. "Exploitable" raises at once (D1).** A record with `exploitable=yes`
sets `findings.validation_outcome = reproducible` in the same transaction.
The exploitation floor then lifts the finding to at least P1 through the
existing trigger and classifier. No approval: raising risk never waits, as
with severity upgrades today. A raise does not expire (R8 applies to
lowering only); it is replaced only by a later result.

**R3. Lowering is a request (D1).** A record with `exploitable=no` may ask to
lower priority (`priority_effect=lower`). That is allowed only when the
finding is open and its class is P0, P1 or P2. The request is decided under
the approval policy with a new kind, `validation_lower`:

| Class of the finding (`approvalpolicy.ClassOf`) | Floor | Default |
|---|---|---|
| standard | single | peer |
| high | peer | peer |
| critical | peer | security |

Default is two people: the recorder plus one other approver. An organization
may relax a cell down to its floor through the existing approval-policy
settings: owner or administrator, a fresh authenticator code, a reason, and
the change takes effect after the existing 24 hour delay. Self-approval
follows the existing rules (the sole member's own approval with a fresh code,
recorded at critical audit severity). A single-person lowering (where a
policy allows it) is listed in the daily approvals digest like a
single-person false positive.

**R4. One level at most, KEV never below P1 (D1).** An applied lowering moves
the class down by exactly one level, inside the base classification next to
the compensating-control step. The two share that one step: a finding already
lowered by an effective compensating control is not lowered again by a
validation result, and the reason line says so. A finding in CISA KEV is
never taken below P1. The business-impact bump, exploitation floor, ownership
floor and attribution cap still run after it, as today. A tenant priority rule
result is not lowered (a rule is the tenant's explicit statement).

**R5. Lowering never extends a deadline (D1).** An applied lowering never
calls `RelaxForDecision`. The SLA deadline already set stays; the applier's
tighten-only rule keeps it from moving later.

**R6. The reason is visible.** The class reason reads "lowered one level to
P2 (was P1): validated not exploitable here by <name>, approved by <name>,
until <date>". The Validation tab, the priority explanation and the record
show the same.

**R7. Validity (D2).** An applied lowering counts until `expires_at`:

```
expires_at = min(tested_at + validity_days, cycle_end)
validity_days = organization setting, default 90, allowed 1..180
cycle_end = end of the bound cycle's end_date (UTC), or its closed_at if it closed earlier
```

The bound cycle is the active cycle whose scope snapshot holds the finding's
asset when the record is made (the earliest `end_date` if several, none if no
active cycle holds it). `tested_at` may not be in the future (5 minutes of
clock skew allowed) or more than 30 days old. Raising `validity_days` is a
relaxation (owner or administrator, step-up, reason, 24 hour delay);
shortening it takes effect at once and also caps standing effects at the next
controller run.

**R8. Expiry returns priority by itself (D2).** When `expires_at` passes, the
controller sets `effect_state=expired` and restores the outcome the record
replaced (`outcome_before`), but only while `findings.validation_outcome` is
still the `not_exploitable` this record set (compare and set). The finding is
re-classified through `finding_priority_queue`. The recorder and the approvers
are told, grouped, with a "re-validate" link.

**R9. A material change suspends (D2).** While a lowering is applied, any of
these sets `effect_state=suspended`, removes the effect and tells the
recorder: severity up, KEV added, EPSS crossing the threshold, a new
validated exploit (a machine re-check reproducing it), the finding reopened,
the asset newly internet exposed or a crown jewel, or the cited compensating
control failing, expiring or being retired. The baseline facts are captured
at approval with the class before lowering (`priority_before`), so the
lowering itself never triggers a suspension. A **pending** request on a
finding whose facts change materially expires (the approver approves what
the recorder saw). A suspended effect never comes back by itself: a new
record is needed.

**R10. Withdraw.** The recorder, or anyone with `findings:approve` over the
finding, may withdraw a pending request or an applied effect at any time,
with a reason. It always raises risk back, so it needs no approval.

**R11. Evidence safety.** Evidence items go through the existing typed
evidence service (origin `manual`): masked, secrets encrypted, revealed only
through the audited Show (`findings:evidence:reveal`, recent sign-in).
Summary, method note and each item are capped at 4 KiB of text; at most 5
items per record. There is no exploit-code field. Attachments use the
existing hygiene, executable and script types are refused, and text
attachments are secret-scanned before storage. The form says "describe the
check, do not paste exploit code".

**R12. What counts.** Only an `applied` lowering counts as "downgraded after
validation" in the figures of RFC-156. Pending, rejected, withdrawn and
inconclusive records count as "validated" only.

## 4. Data model

One expand migration (`make -C server migration-new name=validation_records`)
and one validate migration.

`validation_evidence` gains nullable columns; machine rows leave them NULL:

| Column | Type and rule |
|---|---|
| `recorded_by` | uuid, FK users ON DELETE SET NULL |
| `method` | varchar(32), CHECK `manual_exploit`, `config_review`, `manual_reachability`, `control_assessment`, `pentest`, `other` |
| `exploitable` | varchar(16), CHECK `yes`, `no`, `inconclusive` |
| `control_behaviour` | varchar(16), CHECK `prevented`, `detected`, `responded`, `missed`, `not_assessed` |
| `compensating_control_id` | uuid, FK `(tenant_id, compensating_control_id)` to `compensating_controls (tenant_id, id)` |
| `environment` | varchar(16), CHECK `production`, `staging`, `other` |
| `tested_at` | timestamptz |
| `cycle_id` | uuid, FK `(tenant_id, cycle_id)` to `ctem_cycles (tenant_id, id)` ON DELETE SET NULL (cycle_id) |
| `priority_effect` | varchar(8), CHECK `none`, `raise`, `lower` |
| `effect_state` | varchar(20), CHECK `none`, `pending_approval`, `applied`, `rejected`, `withdrawn`, `expired`, `suspended` |
| `priority_before`, `priority_after` | varchar(4), CHECK P0..P3 |
| `outcome_before` | varchar(20), the finding's `validation_outcome` this record replaced |
| `tier`, `required_approvals`, `decide_by` | as on `finding_severity_requests` |
| `decided_by`, `decided_at`, `decision_note` | the final decision |
| `expires_at` | timestamptz |
| `state_reason` | varchar(300): why it expired, was suspended or withdrawn |

- `executor_kind` gets the value `person` (no CHECK exists today; the domain
  validates it). A person row requires `method`, `exploitable`, `tested_at`
  and `priority_effect` (CHECK `executor_kind <> 'person' OR (...)`).
  `recorded_by` is not required by the CHECK: an erased user sets it NULL and
  the record must survive.
- A unique index `(tenant_id, id)` on `validation_evidence`, and the same on
  `compensating_controls` and `ctem_cycles` where missing (built
  `CONCURRENTLY` in their own migration), so composite keys can point at them.
- FK `(tenant_id, finding_id)` to `findings (tenant_id, id)` ON DELETE CASCADE,
  added `NOT VALID`. It is validated only after a rehearsal on a restored
  backup shows no orphan rows; if there are orphans, the PR reports them and
  the FK stays `NOT VALID` (new rows are still checked).
- Partial unique index: one `pending_approval` and one `applied` lowering per
  finding: `(tenant_id, finding_id) WHERE effect_state IN
  ('pending_approval','applied') AND priority_effect = 'lower'`.
- Partial index `(expires_at) WHERE effect_state = 'applied'` for the expiry
  controller.
- `finding_evidence` gains `validation_record_id uuid`, FK `(tenant_id,
  validation_record_id)` to `validation_evidence (tenant_id, id)`: the evidence
  items of a record.
- `findings.validation_outcome` CHECK widens to add `not_exploitable`: drop
  and re-add the constraint `NOT VALID`, then `VALIDATE CONSTRAINT` in the
  validate migration (a scan under SHARE UPDATE EXCLUSIVE, no rewrite).
- `approval_signoffs.subject_type` CHECK adds `validation_record`.
- Content columns are written once. Only the state columns change, under a
  row lock (`SELECT ... FOR UPDATE`), through a state machine:

```
none (exploitable=yes, raise applied at insert)
pending_approval -> applied | rejected | withdrawn | expired
applied          -> expired | suspended | withdrawn
```

Nothing is deleted. Down migrations drop only what the up added.

## 5. API

Contract regenerated; route coverage and data-scope registries updated
(`api-route` skill).

| Verb | Path | Permission | Step-up | Notes |
|---|---|---|---|---|
| POST | `/api/v1/findings/{id}/validation-records` | `findings:verify` + finding's asset in data scope | sensitive when `priority_effect=lower` | Reason required for `lower` (tier `MinNoteLength`). 10 records per user per finding per 24 h; the tenant's evidence daily cap applies |
| GET | `/api/v1/findings/{id}/validation-records` | `findings:read` + data scope | none | Newest first; evidence items masked |
| POST | `/api/v1/findings/{id}/validation-records/{rid}/approve` | `findings:approve` + data scope | sensitive (critical for the sole member's own approval) | 409 unless `pending_approval`; eligibility from the policy evaluation |
| POST | `/api/v1/findings/{id}/validation-records/{rid}/reject` | `findings:approve` + data scope | none | Reason required |
| POST | `/api/v1/findings/{id}/validation-records/{rid}/withdraw` | the recorder, or `findings:approve` + data scope | none | Pending or applied; reason required |

- The approvals queue (`GET /api/v1/approvals`) and the daily digest list
  pending `validation_lower` requests next to finding status requests, with
  the same visibility rule (only requests the viewer may decide, finding in
  their data scope, titles but never summaries or evidence).
- The record list is part of the finding timeline read.
- Responses carry `effect_state`, `priority_before`, `priority_after`,
  `expires_at` and the policy evaluation (tier, approvals given and needed),
  never the recorder's evidence in clear.
- A foreign or out-of-scope finding, record or control id answers 404.

## 6. Permissions and step-up

No new permission. Recording uses `findings:verify` (a person confirming
state); deciding uses `findings:approve`. The recorder may never approve their
own request except through the existing sole-member path. A recorder who owns
the asset is not counted as an approver (existing `Candidate` rule).
Settings changes (policy cells, `validity_days`) use the existing approval
settings route: owner or administrator, `settings:write`, fresh code, reason,
24 hour delay for relaxations.

## 7. Tenant isolation

- Every query carries `tenant_id`; composite foreign keys make a row unable to
  point at another tenant's finding, control or cycle (a test inserts each
  foreign id and expects a refusal).
- Controllers read across tenants only to find due work; every write names
  the record's tenant and runs in one transaction with its timeline entry and
  audit row.
- Data scope: recording and deciding need the finding's asset in the actor's
  scope; a scoped approver never sees or decides requests outside it.

## 8. Audit and notices

Through `audit.NewSuccessEvent`, each with the finding, record and actor:

| Action | Severity |
|---|---|
| `finding.validation_recorded` | medium |
| `finding.validation_lower_requested` | high |
| `finding.validation_lower_approved` | high (critical when one person decided) |
| `finding.validation_lower_rejected` | medium |
| `finding.validation_withdrawn` | medium |
| `finding.validation_effect_expired` | low |
| `finding.validation_effect_suspended` | medium |

Notices go through the outbox and the in-app notifications: approvers on a
request (like false-positive requests), the recorder on decision, expiry and
suspension, one grouped notice per person per controller run.

## 9. Controllers

- **`validation-effect-expiry`**: leased, hourly. Moves applied effects past
  `expires_at` to `expired` in batches of 500, each finding re-classified
  through `finding_priority_queue` (no recompute storm), then one grouped
  notice per recipient.
- **Material change**: `approval_material_change` gains applied
  `validation_lower` effects and pending requests as decisions it checks (R9).
  The compensating-control triggers run inline on the control's status,
  test-result and expiry writes.

## 10. Figures it feeds

Defined and frozen per cycle in RFC-156: validation downgrade share (R12),
validated count, and time from validation to ticket. The existing
`downgrade_pct` of `GET /api/v1/validation/coverage` keeps its RFC-011.2
meaning; RFC-156 reports both meanings side by side, labelled.

## 11. UI surfaces

Boards (redesign canvas): **FindingDetail-Validation** (the tab: records,
state chips, expiry), **FindingDetail-Validation-Record** (the "Record
validation" dialog), and the approvals row in the Inbox approvals tab (kind
`validation_lower`; the board still has to be drawn). **AttackPaths-Step-Validate**
is the path-step variant; it is designed in the RFC-153 amendment (plan wave
2), not here.

Simplest path: one main action "Record validation" on the Validation tab.
Exploitable yes, no or not sure; method; a summary. Environment, control,
tested-at and evidence are folded under "More detail". Choosing "No" shows
"Ask to lower priority" with the four-eyes note and the date it would end.
The live console gets the dialog on the shared dialog frame before the
redesign (plan item 1.9), en and vi.

## 12. Threat cases

| Threat | Closed by | Test |
|---|---|---|
| An insider lowers a P0 or P1 to dodge the SLA | Two people by default, step-up, one level, KEV floor, expiry, digest, high audit, deadline never extended | Self-approve refused under the default; deadline unchanged after apply; KEV stays P1 |
| One person lowers where the policy allows it | Reason, digest listing, material-change suspension, critical audit | Digest contains the decision |
| Cross-tenant ids (finding, control, cycle, record, evidence) | Composite FKs, tenant predicate, 404 | One test per id kind |
| Recorder or approver outside the asset's data scope | Data-scope check on every route | 404 for both |
| Approve after the finding changed | A material change expires the pending request | Change between request and approve gives 409 |
| Double approve or replay | State machine under a row lock | Two concurrent approves apply once |
| Backdated or stale tests | `tested_at` within 30 days, not in the future; expiry from `tested_at` | Both refusals |
| Secrets or exploit code in evidence | Mask, encrypt, audited Show, caps, type refusal, secret scan, no code field | Masked in the response; script upload refused |
| Metric gaming | Only applied lowerings count; each carries before and after | Pending and rejected not counted |
| Stacking with a control to drop two levels | Shared single step (R4) | Control plus record still one level |
| Spam | Per-user rate limit, tenant daily cap | 11th record in 24 h refused |
| Expiry storm | Batches of 500 through the queue | Queue drains within one run on 10k rows |

## 13. Rollout (expand, then contract)

1. Expand migration (columns, CHECKs `NOT VALID`, indexes, signoff subject
   type) and validate migration; rehearse on a restored backup and measure
   the `findings` CHECK validation lock.
2. Record and list routes, raise path (no lowering yet).
3. Lowering request, approve, reject, withdraw; policy kind.
4. Priority effect, expiry controller, suspension.
5. Live UI dialog and approvals row.

No contract step: nothing is renamed or removed. Each step is its own PR
(plan items 1.1 to 1.4, 1.9), all security-sensitive.

## 14. Out of scope

- Test-case templates or a library of reusable checks.
- A second reviewer for `exploitable=yes`.
- AI-suggested results.
- Linking a record to a simulation run (needs real execution, RFC-012).
- Proof of attack-path steps (RFC-153 amendment).
- A score effect for "blocked" path steps.

## 15. Open questions for the owner

1. **Critical-class default.** This RFC sets the `validation_lower` default
   for the critical class to the security tier (one approver from the
   security pool). Is that right, or should it be peer like the other
   classes?
2. **Tenant priority rules.** A rule result is not lowered by a validation
   record (R4). Should a validation lowering also apply on top of a rule?
3. **Raises expire?** R2 keeps a person's "exploitable" raise until a later
   result. Should it also expire after the validity window?
4. **Production testing.** Should a record with `environment=production` and
   method `manual_exploit` require a written authorization reference, like
   the production rule planned for simulations? (Legal weight: owner only.)
</content>
</invoke>
