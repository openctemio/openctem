### Added: attack surface posture score

- Attack surface > Posture grades the external attack surface from A to F, for the organization and for each root domain. Six categories contribute: vulnerabilities, hijackable subdomains, exposed services, cloud storage, misconfiguration, and suspicious activity.
- For each category the page shows the score once its issues are fixed. It also shows a fix plan that reaches the next grade and the risk reduction by asset criticality. Formula: `api/docs/architecture/easm-posture.md`.
- Figures are precomputed per asset on each organization's schedule (manual, 1 h, 6 h by default, or 24 h), or on demand with Recalculate now (at most once every 5 minutes). Every read applies the reader's data scope.
- New routes:
  - `GET /api/v1/attack-surface/posture` (`assets:read`);
  - `POST /api/v1/attack-surface/posture/refresh` (`assets:write`, audited);
  - `PUT /api/v1/attack-surface/posture/schedule` (`settings:write`, audited).
- New dashboard metric `surface.posture`. New controller `easm-posture`. Migration `easm_posture` adds two empty tables.
