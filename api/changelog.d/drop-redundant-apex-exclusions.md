### Changed: the apex exclusions the wildcard rule change made redundant are removed

- When `*.x` meant "the subdomains only", an upgrade added an apex exclusion
  `x` beside every wildcard exclusion `*.x` (created by
  `system:migration-000292`). Since `*.x` covers `x` again (RFC-054 S1), such
  a row is redundant while its wildcard parent is in effect at least as
  long. Migration `001164` deletes those rows: untouched since the upgrade,
  active, and under an active, approved parent that never expires or expires
  no earlier.
- Every other such row (its parent was removed, deactivated, shortened or is
  still pending, or a person changed it) stays as a standalone exclusion,
  with a reason that says so: "Apex of the former wildcard exclusion
  `*.x` (id), kept as its own exclusion when the wildcard rule changed
  (2026-10)", followed by the original reason.
- Nothing that is excluded today becomes scannable. No audit rows are written
  from SQL (the audit log is hash-chained by the application); this entry
  records the change. The down migration restores the previous rows and
  wording.
