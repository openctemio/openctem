# Finding severity override

Status: shipped (migrations `finding_severity_override`, `finding_severity_override_validate`).

An analyst can change a finding's severity. The change is a decision with a
reason, it keeps the severity the tools reported, it recomputes the finding's
priority, SLA deadline and "Why it matters" at once, and no later scan reverts
it.

## Model

| Column (`findings`) | Meaning |
|---|---|
| `severity` | the **effective** severity. Every reader (filters, dashboards, the priority classifier, SLA windows, the approval policy) reads it, unchanged |
| `source_severity` | what the tools reported, kept while an override stands; `NULL` means "equal to `severity`" |
| `severity_override_reason`, `severity_overridden_by`, `severity_overridden_at` | the analyst's override; `severity_overridden_at IS NULL` means no override |

Effective = override, else source. Existing findings keep their severity as the
effective one, with no override. Domain: `pkg/domain/vulnerability/finding_severity_override.go`.

## Changing the severity

`PATCH /api/v1/findings/{id}/severity` with `{"severity": "...", "reason": "..."}`
or `{"restore": true, "reason": "..."}` (`findings:severity`; the finding must be
in the caller's data scope, otherwise 404).

- **Reason**: required (1 to 1000 characters).
- **Upgrade**: applies at once.
- **Downgrade** of the effective severity (a restore included, when it lowers it):
  decided by the organization's false-positive approval policy, the same
  evaluator and level (`all`, `high_and_above`, `off`, plus the policy's tiers)
  as a false positive (RFC-111). When the caller may decide alone (single tier:
  they hold `findings:approve`, the level allows it, they do not own the asset)
  it applies at once; otherwise it becomes a **pending request** (202) in
  `finding_severity_requests`, one per finding, and the finding keeps its
  severity. The people who may approve are told in-app.
- **Restore**: ends the override; the reported severity applies again.

The answer is the finding with its recomputed `priority_class`,
`priority_class_reason`, `sla_deadline`, `source_severity`,
`severity_override` and `pending_severity_request`.

## Recompute

On an applied change, for an open finding, the service runs the same
`PriorityClassificationService.EnrichAndClassifyBatch` and SLA applier that
ingest and the finding-priority worker use (one code path), then writes the
severity, its provenance and the recomputed columns in one statement guarded
on the severity the decision was made from (a concurrent change answers 409).
The classifier writes the priority audit entry and the priority-change outbox
event; the findings triggers mark dashboard facts dirty and queue the asset
for the finding-priority worker. A closed finding keeps the class and deadline
it had when it closed.

SLA: an upgrade tightens as every recompute does (`min(old, now + SLA)`). A
downgrade that was allowed (alone or approved) is the explicit decision that
may extend the deadline: `first_detected_at + SLA(new class)` when that is
later, never counted from now, written in a transaction marked
`openctem.sla_restart` (the database guard `trg_findings_sla_deadline_guard`
refuses any other extension).

## Requests

`POST /api/v1/findings/{id}/severity-requests/{request_id}/approve` and
`/reject` (`findings:approve`), `/cancel` (`findings:severity`, the requester
only).

- Approve evaluates the policy again on the facts of that moment; the
  requester and the owners of the finding's asset never approve; the approver
  must have the finding in scope; step-up when the tier asks for it; each
  approval is a row in `approval_signoffs` (`subject_type = severity_request`).
  The last approval needed applies the change in the same transaction as the
  request row, only while the finding still has the severity the request was
  made from (otherwise 409: request again). The override's author is the
  requester; the approver is on the request and the timeline.
- Reject needs a reason; the requester withdraws instead of rejecting.
- A request not decided within the policy's decision window expires.

## Ingest and re-sightings

While an override stands, the re-sighting path (`EnrichBatchByFingerprints`,
keep-the-highest rule), the ingest upsert, KEV escalation, license verdicts
and correlation write the reported severity to `source_severity` only
(`reportedSeveritySetSQL` / `reportedSeverityMaxSetSQL` read the row's current
override, so a concurrent override is never lost). When `source_severity`
changes under an override, the trigger `trg_findings_severity_source_review`
adds a `severity_source_changed` timeline entry asking for a review; the
override stands.

## Audit

Timeline: `severity_changed` (old, new, source, reason, priority, deadline;
approver and request id when approved), `severity_change_requested`,
`severity_change_rejected`, `severity_change_canceled`,
`severity_source_changed`. Audit log: `finding.severity_changed`,
`finding.severity_requested`, `finding.severity_request_closed` with old, new
and reason.

## Threat model

Lowering a severity hides risk as a false positive does (priority, SLA
urgency, dashboards). Controls: least-privilege gate (`findings:severity`,
separate from fixing), data scope by id (404), tenant on every statement,
reason required, downgrade under the organization's approval policy with its
exclusions and step-up, re-evaluation and a stale-severity guard at approval,
an SLA extension only from an allowed downgrade and only up to the first
detection's window, and every step on the timeline and in the audit log. A
scan cannot silently undo a decision, and a tool's changed opinion is
surfaced for review.

## Web

The finding detail shows the severity with "Analyst · source: Medium" (reason
in a tooltip) and "Restore source severity", asks for a reason in a dialog,
writes the answer's priority, deadline and reason into the cached finding at
once, and shows a pending request with Approve / Reject (approvers) or
Withdraw (the requester).

## Key files

- `api/internal/app/finding/severity_override.go`
- `api/internal/infra/postgres/finding_severity_override.go`, `finding_severity_columns.go`
- `api/internal/infra/http/handler/finding_severity_handler.go`
- `api/internal/app/sla/applier.go` (`RelaxForDecision`)
- `web/src/features/findings/hooks/use-finding-triage.tsx`, `components/severity-change-dialog.tsx`, `components/detail/severity-provenance.tsx`
