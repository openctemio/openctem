### Security: foreign assignee names and emails scrubbed from finding history (migration 001012)

- Finding activity rows that recorded the name and email of an assignee
  outside the organization (possible before #1096) now show
  `Former assignee (not in this organization)`; the email is removed. Rows,
  ids and timestamps are kept. One-way by design; see
  `docs/deployment/safe-deploy-and-migrations.md` ("Foreign assignee scrub").
- A remediation campaign's validator team (`assigned_team`) must be a group
  of the campaign's organization; any group id used to be stored.
