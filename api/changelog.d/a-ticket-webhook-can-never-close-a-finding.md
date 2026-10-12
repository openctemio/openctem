### Security: a ticket webhook can never close a finding

- **Jira and GitHub inbound sync only report work state** (research 18 F5).
  A Jira webhook may move a finding to `confirmed`, `in_progress` or
  `fix_applied`, never to `resolved`, `false_positive`, `accepted` or
  `duplicate`: a webhook has no person who holds `findings:verify` or an
  approval. A ticketing integration whose `ticketing.status_inbound` maps a
  Jira status to a closing status is refused on save (400); such entries in
  stored configs are ignored, and the webhook checks the target again before
  applying it. The stock Jira "Duplicate" mapping was removed (marking a
  duplicate is a triage decision, `POST /findings/{id}/duplicates`).
- The tenant's own `status_inbound` overlay now applies to inbound webhooks
  (before, only the stock map did), within the same three statuses.
- Inbound status changes are recorded in the finding's history with the
  integration (`jira` / `github`) and the ticket as the actor.
