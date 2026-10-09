### Security: re-scoring a finding needs its own permission

- `PATCH /api/v1/findings/{id}/severity` and `/classify` now need
  `findings:severity`, and finding comments and reactions need
  `findings:comment`. Both were gated by `findings:write`, so whoever could
  comment or record remediation steps could also lower a finding severity.
- Migration 001534 grants both permissions to every role, built-in or custom,
  that held `findings:write`, so nobody else loses an ability. The built-in
  Researcher role gets `findings:comment` only: researchers report and discuss
  findings, and triage owns severity. Remove `findings:severity` from a custom role (the
  remediation-owner template leaves it out) to stop its holders re-scoring.
- The web console offers the comment box and the severity picker from those
  routes gates.
