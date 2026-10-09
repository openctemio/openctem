### Security: re-scoring a finding needs its own permission

- `PATCH /api/v1/findings/{id}/severity` and `/classify` now need
  `findings:severity`, and finding comments and reactions need
  `findings:comment`. Both were gated by `findings:write`, so whoever could
  comment or record remediation steps could also lower a finding severity.
- Migration 001447 grants both permissions to every role, built-in or custom,
  that held `findings:write` (recorded in `granular_permission_backfill`), so
  nobody loses an ability. Remove `findings:severity` from a custom role (the
  remediation-owner template leaves it out) to stop its holders re-scoring.
- The web console offers the comment box and the severity picker from those
  routes gates.
