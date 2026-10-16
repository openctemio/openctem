### Added: approvers clear the review flag of a suppression rule

- `POST /api/v1/suppressions/{id}/reviewed` (`findings:suppressions:approve`) clears the review flag the platform set on a rule that had no end date; the rule keeps its end. Audited as `suppression_rule.reviewed` with the flag before and after; 409 when the rule is not flagged. The rule's detail in Exceptions has a "Mark as reviewed" button for approvers.

### Behaviour change: approved suppression rules without an end now expire

- **Upgrade note:** since migration `suppression_rule_end_backfill`, an approved suppression rule that had no end date expires 90 days after the deploy that ran the migration, and the findings it suppressed reopen then (with a new SLA clock where they were accepted risks). Operators: review the rules flagged "Review" in Exceptions and submit a new rule before that date for any suppression that must continue.

### Security: a suppression rule's requester cannot clear its review flag

- Clearing the review flag of one's own rule is refused (403, audited as a
  denied `suppression_rule.reviewed`) unless the requester is the sole
  approver: the owner with no other approver and no recent approver change,
  with a reason and a fresh authenticator code, like approving their own
  rule. The web asks for the reason and the code in that case.
