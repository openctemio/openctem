# Suppression rules

A suppression rule is an organization's decision that a class of findings is a
false positive or an accepted risk: a tool rule id (exact, or a prefix ending
in `*`), optionally narrowed to a tool, a file path glob (`*`, `**`) and one
asset. It is requested by one person and approved by another, and it always
expires. Tables: `suppression_rules`, `finding_suppressions` (which rule
suppressed which finding), `suppression_rule_audit` (the rule's own trail).

Code: `pkg/domain/suppression` (entity, matcher `Rule.Matches` /
`Rule.MatchesCriteria`, service), `internal/infra/postgres/suppression_repository.go`
and `suppression_apply.go`, `internal/infra/http/handler/suppression_handler.go`,
routes in `registerSuppressionRoutes` (`internal/infra/http/routes/scanning.go`).

## Lifecycle

| Step | Who | What happens |
|---|---|---|
| Request | `findings:suppressions:write` | A pending rule. An asset-bound rule must name an asset the requester may see. The rule has an end (`expires_at`): 90 days when none is given, at most 365 days ahead; the end cannot be removed. Renewal is a new rule, reviewed and approved again. |
| Preview | `findings:suppressions:approve` | `GET /api/v1/suppressions/{id}/preview` returns `{matching_open_findings, capped, limit, in_scope_findings, sample}`: the open findings an approval would close now, how many of them are on assets the caller's data scope covers, and the first 10 of those (title, severity, asset, path; never evidence). |
| Approve | `findings:suppressions:approve` | Four-eyes: the approver is not the requester, unless the owner is the only eligible approver and sends `self_approval_reason` and a fresh `totp_code` from their authenticator app (audited Critical; a refused own approval is audited High as `suppression_rule.self_approval_refused`). The request names the `reviewed_updated_at` it approves; a rule edited since is refused (409). The approval closes the open findings the rule matches (below). |
| Reject | `findings:suppressions:approve` | The rule never applies. |
| Expire / delete | data-expiration controller / `findings:suppressions:delete` | The rule's suppressions are lifted (below). |

## Every rule ends

A rule hides findings from the backlog and the CI gate, so a rule that never
ends hides them for good. The domain gives every rule an end
(`suppression.RuleEnd`: default `DefaultRuleDuration` = 90 days, at most
`MaxRuleDuration` = 365 days), the database refuses a row without one
(`chk_suppression_rules_expires_at_set`, with a 90-day column default for
writers that name none, such as CI inline-ignore requests), and the expiry job
lifts the rule's suppressions when it passes.

Rules made before the end was required were given 90 days from the upgrade by
migration `suppression_rule_end_backfill`; the pending and approved ones carry
a review flag (`review_flagged_at`, `review_reason = no_end_date`), shown as a
"Review" badge in the list and a callout in the rule's detail, so an approver
looks at them again. An edit of a pending rule clears the flag; for an approved
rule (which cannot be edited) an approver clears it with
`POST /api/v1/suppressions/{id}/reviewed` (`findings:suppressions:approve`,
409 when not flagged): the rule keeps its end, the rule's trail records the
cleared flag and the tenant audit log has `suppression_rule.reviewed` with the
flag before and after.

## Where an active rule applies

- **Approval (existing findings).** In the approval's transaction the rule row
  is locked and re-checked (still pending, still the reviewed version), then
  every open finding of the organization the rule matches gets the rule's
  disposition: `false_positive` for a false-positive rule, `accepted` for an
  accepted-risk or won't-fix rule, with resolution `suppressed`. Each changed
  finding gets a `finding_suppressions` link (`applied_by = approval`) and a
  `status_changed` activity naming the approver and the rule; the rule's
  `approved` audit entry and the tenant audit log carry the count
  (`applied_findings`, `capped`). The response returns the same count.
- **Ingest (new findings).** A new finding a rule matches lands with the
  rule's disposition before it is stored (`internal/app/ingest/processor_suppression.go`);
  the suppressions module toggle is honored.
- **CI gate.** The gate excludes a finding an active rule covers at evaluation
  time, so a rule approved after a finding was first seen counts at once.
- **Sensors.** Sensors read the active rules of their organization.

### Which findings an approval changes

- Open work only: `vulnerability.SuppressionApplyFromStatuses(disposition)`,
  the active statuses the platform may move to that disposition. A
  false-positive rule closes `new`, `confirmed`, `in_progress` and
  `fix_applied`; an accepted-risk rule closes `new` and `confirmed` and leaves
  work in progress alone (someone decided to fix it).
- Never: findings already `false_positive`, `accepted`, `duplicate`,
  or `resolved`; findings a person reported (sources
  `pentest`, `manual`, `bug_bounty`, `red_team`); other organizations'
  findings; findings of other assets when the rule is asset-bound; findings
  without a file path when the rule has a path condition.
- Matching is the rule's own matcher. SQL narrows the candidates (tenant, open
  status, source, tool, rule id or LIKE-escaped prefix, asset, path present)
  page by page in id order; Go applies `Rule.MatchesCriteria`, globs included.
  The preview runs the same code, so its number is what the approval changes
  (barring findings that change in between).
- Bounded: one approval changes at most 10 000 findings
  (`suppression.MaxFindingsAppliedOnApprove`). Beyond that the preview and the
  response say `capped`; the remaining findings stay open, and the CI gate and
  ingest still honor the rule for them.
- The update re-checks tenant, status and source under a row lock, so a
  finding someone moved after it was read is skipped.

## Lifting

When a rule is deleted or expires, every finding linked to it that is still in
the suppression's disposition (resolution `suppressed`, status `false_positive`
or `accepted`) is re-linked to another active rule that matches it, or reopened
as `new` with a `reopened` activity (`liftSuppressionsInTx`). This reverses
what the approval and ingest applied, whichever of the two linked the finding.
A finding someone has moved since is left alone.

## Security

- Tenant: every query carries the rule's `tenant_id`; the rule is loaded by
  tenant and id, so another organization's rule is 404 for both the preview and
  the approval. Tests: `suppression_apply_db_test.go` (cross-tenant negative).
- Data scope: approval acts organization-wide, so `matching_open_findings` is
  organization-wide too. It is a number, never a finding, and only people who
  may approve see it (`authorization-matrix.md`). The sample and
  `in_scope_findings` are limited to the caller's data scope (the same
  `FilterForCaller` as every by-id read): a finding on an asset the caller
  cannot see is counted in the organization total and never listed. Without a
  scope filter wired the sample is empty (fail closed). Tests:
  `suppression_preview_sample_db_test.go` (scope and cross-tenant negatives).
- Separation of duties: the requester cannot approve their own rule while
  someone else can; a lone owner approves their own rule only with a reason
  and a fresh authenticator code, never as a side effect of a plain approve,
  and not within 7 days of any member being suspended, offboarded or removed; the approval pins the reviewed version, so a rule widened
  after review cannot be approved by mistake.
- Abuse: a broad rule (for example rule id `*`) closes at most
  the cap per approval, and every change is attributable (activity per finding,
  rule audit entry, tenant audit log) and reversible (delete the rule).
