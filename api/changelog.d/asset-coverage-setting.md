### Added: an organization setting for automatic coverage

- Scoping > Settings gains "Automatic coverage" (`auto_coverage` on
  `GET/PUT /api/v1/scope/settings`, with `auto_coverage_effective`): on by
  default; while the scan approval mode in force is Strict it is off until
  the organization turns it on (owner decision D1). Changing it needs the
  scope approver permission and a recent re-authentication, is audited and
  notifies every administrator, like the other scope settings. Omitted on a
  PUT, the stored choice is kept.
