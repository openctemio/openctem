### Added: exploration leads for people (API)

- `GET /api/v1/exploration/leads` (`assets:read`, groups waiting / next / running / done, keyset paging)
  and `GET /api/v1/exploration/leads/{id}` (links and verdicts) list and read leads within the caller's
  data scope: a lead is seen when its subject asset is; out of scope answers 404.
- `POST /api/v1/exploration/leads` (`scans:execute`) asks a catalog question about an asset in the
  caller's data scope; the tier decides its first state as for a rule's lead.
- `POST /api/v1/exploration/leads/approve` (`scans:approve` and a fresh step-up) lets up to 100 waiting
  leads run; `POST /api/v1/exploration/leads/dismiss` (`scans:approve`) closes up to 100 live leads.
  Results are per lead. Approvals and dismissals are audited (`exploration.lead_approved`,
  `exploration.lead_dismissed`, with the reason).
