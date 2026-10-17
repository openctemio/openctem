### Added: finding status moves follow the organization's published lifecycle

- Every status path (`PATCH /findings/{id}/status`, bulk status, the fix-applied, verify and reject
  actions, remediation group and campaign resolves, ticket webhooks, approval requests) is also decided by
  the organization's published lifecycle (RFC-110). It can only narrow the platform's decision: a longer
  note, required fields, a required permission, keeping automation or ticket sync off a move. It never
  lets a move past `findings:verify`, the evidence rules, the fix-claim rules or four-eyes approval.
- `PATCH /findings/{id}/status` takes `sub_status_id` and `fields`; the finding resource carries
  `sub_status_id`; `GET /findings/{id}/transitions` and the bulk preview list sub-status moves and what each
  needs. A sub-status changes only through these moves, each on the timeline with the lifecycle version
  that decided it. Organizations without a published lifecycle see no change.
