### Behaviour change: creating an SLA policy no longer makes it the default

- A new SLA policy is not the tenant default unless it is the tenant's first; replacing the default is an explicit "Make default" action with a confirmation, done in one transaction (console and `PUT /sla-policies/{id}` with `is_default: true`). The default policy can no longer be deactivated, un-defaulted or deleted (409 `SLA_DEFAULT_POLICY_PROTECTED`).
- The SLA policy dialog moves all its text to the en and vi dictionaries.

### Fixed: SLA default policy races and inactive default

- Two concurrent make-default calls could leave two defaults, and an inactive default still governed findings without an asset. Create now applies the same window validation as update.
- Migration `sla_policies_default_safety`: unsets duplicate or inactive tenant defaults (keeps the oldest active one), clamps any severity window outside 1..365 (info 0..365) into that range so the constraint can be validated, then adds a unique index on the tenant default and CHECK constraints on the default and the severity windows (1..365, info 0..365).
- **Upgrade note:** a tenant that had several defaults or an inactive default keeps only its oldest active default after this migration; the down migration removes the constraints but does not restore the unset flags.

### Removed: unused SLA service code

- Removed `CheckSLACompliance`, `CalculateSLADeadline` and the unscoped `ExistsByAsset` (no callers).
