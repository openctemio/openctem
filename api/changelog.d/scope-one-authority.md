### Security: one scope authority for typed and inventory targets; confirming ownership no longer authorizes scans

- Every active-probe path (scan create/run, quick scan, `POST /commands`,
  pipelines, coverage, retests and validation, simulations, connector scans)
  now asks one authority (RFC-054 §4.2): a scope target, or a name at or under
  a root-domain seed or verified domain of the tenant.
- Typed text under a seed or verified domain is now accepted, as the same name
  in the inventory already was.
- An internet-facing asset confirmed on its Ownership tab but outside every
  scope target, seed and verified domain is no longer probed;
  `GET /assets/{id}/attribution` reports `active_checks_blocked_by:
  out_of_scope`.
- Typed text naming an internet host or public address is refused on system
  paths too when nothing covers it.
- **Upgrade note:** assets that were scannable only because someone confirmed
  them on the Ownership tab stop being scanned. Runs list them in their
  warnings. Add a scope target (or seed) that covers them.
