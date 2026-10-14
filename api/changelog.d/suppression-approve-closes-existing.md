### Behaviour change: approving a suppression rule closes the open findings it matches

- Approving a suppression rule now also gives the organization's open findings
  that the rule matches its disposition (`false_positive`, or `accepted` for an
  accepted-risk or won't-fix rule; resolution `suppressed`), in the same
  transaction as the approval. Before, only findings first seen after the
  approval were suppressed. Findings already decided, resolved or reported by
  a person (pentest, manual, bug bounty, red team) are left alone; an
  accepted-risk rule leaves work in progress alone.
- One approval changes at most 10 000 findings; the response
  (`applied_findings`, `capped`), the rule's audit entry and the audit log
  carry the count, and each finding gets an activity naming the approver.
  Deleting the rule or its expiry reopens them as before.
- New `GET /api/v1/suppressions/{id}/preview` (`findings:suppressions:approve`)
  returns how many open findings an approval would close; the console's
  approval dialog shows it.
