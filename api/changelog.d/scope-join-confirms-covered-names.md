### Behaviour change: names a scope target or seed covers are confirmed without review

- A discovered name (Certificate Transparency or a tenant scan) that an active,
  permanent domain scope target (`x`, `*.x`) or a root-domain seed covers is
  confirmed into the inventory with the new rule `matches_scope_target`
  (RFC-054 §4.3). An IP address is confirmed only when an IP, range or CIDR
  scope entry contains it. Exclusions, tombstones and rejected parent names
  still win; a person's decision is never changed.
- Removing the scope target keeps the asset and its findings; active scanning
  of it stops at once.
- **Backfill:** at start-up (and every 6 h) the API re-evaluates automatic
  `needs_review`/`candidate` records against the current scope targets and
  seeds, tenant by tenant, and confirms the covered ones; each run that
  confirms names is audited as `asset.attribution_auto_confirmed`. Live had
  10 such names under `*.example.co.uk`.
