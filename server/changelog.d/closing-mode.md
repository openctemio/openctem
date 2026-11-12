### Added: closing mode per organization

- Each organization chooses how findings close without a person: `auto` (per the tier rule), `review` (every close becomes a proposal) or `off`. `GET|PUT /api/v1/organization/settings/closure`, owner or administrator.
- New organizations start in `auto`; existing organizations read as `review` (no data migration).
- In `auto`, a covered scan with no fix claimed closes standard and high findings and proposes critical, P0 and KEV ones, unless the owner turns on `critical_auto_close`.
- Loosening the policy needs a recent re-authentication, is audited `tenant.closure_updated` at high severity and notifies owners and administrators; `critical_auto_close` is owner-only. Tightening is immediate.

### Behaviour change: INGEST_COVERAGE_AUTO_RESOLVE=enforce follows the organization's closing mode

- `enforce` (and its new alias `tenant`) now acts per each organization's closing mode and the tier rule instead of closing every covered finding; `off` and `dry_run` (default) are unchanged and close nothing.
- Proposed closes are recorded on the ingest receipt (`coverage.note = review`) and in the coverage dry-run audit entry (`decision = review`).
- The verification plan's covered-scan method follows the same rule.
