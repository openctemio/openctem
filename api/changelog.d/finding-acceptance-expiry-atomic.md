### Fixed: an ended risk acceptance reopens the finding in one transaction, with a new SLA clock

- The hourly acceptance expiry now ends each accepted finding whose
  `acceptance_expires_at` has passed in one transaction: the finding returns
  to `confirmed`, a new SLA clock starts at the reopen (the policy deadline
  for its priority, on track), its approved requests are marked `expired`,
  and the timeline records `acceptance_expired` and `sla_restarted`. Before,
  the request was expired first; a failed finding update left the finding
  accepted for good, with no timeline entry, the old breached deadline and a
  junk resolution text.
- Every accept path records when the acceptance ends: an approved suppression
  rule (its expiry, else 90 days), ingest suppression and re-link to another
  rule, merges that inherit an acceptance, and pentest acceptances.
- Migration `002166` gives accepted findings that still had no end the 90-day
  default from the day it runs, with a timeline note.
