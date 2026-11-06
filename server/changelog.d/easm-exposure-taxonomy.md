### Added: exposure display categories, one-line summaries, in-progress state and severity override

- Every exposure has a fixed display category (exposed ports, hijackable subdomains, email security, SSL/TLS, certificates, ...) and a one-line summary such as "Port 6379 (Redis) is open to the internet", returned as `display_category` and `summary` on the exposure API. `GET /api/v1/exposures?category=` filters by category and `GET /api/v1/exposures/stats` returns `by_category`.
- New exposure types `web_interface_exposed`, `mcp_server_exposed` and `mail_server_blocklisted` (their producers are planned).
- Exposures have an `in_progress` state (still open): `POST /api/v1/exposures/{id}/start-progress` (`findings:write` and `findings:exposures:triage`). Automatic resolutions (closed port, rejected name, DNS check) also resolve in-progress exposures.
- `PATCH /api/v1/exposures/{id}/severity` sets or removes an analyst severity override with a required reason (`findings:severity` and `findings:exposures:triage`), audited as `exposure.severity_changed`. The reported severity is kept and re-sightings never revert the override; the second-approver rule keeps reading the highest reported severity.
- Assets have one derived monitoring state (monitored, not monitored, pending decision, unvalidated, irrelevant, inactive, out of scope): `GET /api/v1/assets?monitoring_state=` filters by it and `?with_triage=true` adds it to each row.
- Migration `20261030200514_exposure_taxonomy_progress_severity` (new CHECK values and four nullable columns on `exposure_events`; no rewrite).
