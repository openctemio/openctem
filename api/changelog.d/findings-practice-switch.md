### Behaviour change: the findings list opens on Vulnerabilities; one click shows Compliance

- A practice switch above the findings list: Vulnerabilities (the default, every practice except compliance),
  Compliance, each other practice that holds findings, and All, with the caller's counts. The choice is part of the
  URL and of saved views (RFC-152).
- New endpoint `GET /api/v1/findings/practice-counts` (`findings:read`): the list's filters with the practice
  condition left out, counted per practice in the caller's scope.
- Settings > SLA policies: a new policy applies to Vulnerabilities or to Compliance; compliance policies are marked
  in the list.
