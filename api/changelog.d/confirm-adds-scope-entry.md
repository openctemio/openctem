### Behaviour change: confirming an asset as ours adds its exact scope entry

- While scan approval is Off or On, a person who confirms a domain, subdomain
  or public address as the organization's (review queue, review by rule
  "accept selected", or the asset's Ownership tab) now also adds the scope
  entry for exactly that name. Scans can reach it without a second step in
  the scope dialog.
- The entry goes through the scope service: guardrails, the deny list, one
  re-authentication for the batch (nothing is saved without it), one notice
  to the administrators and an audit event per entry. Entries carry the
  origin `confirmed_asset`. The answer names each entry, so Undo is an
  ordinary entry delete.
- Never added: anything wider than the name, a name an entry already covers,
  a private or internal name, or a service, certificate or web endpoint.
  Nothing is added for a caller without the scope write permission.
- Under Strict, confirming still records ownership only. The organization
  can turn the behaviour off with the new scope setting
  `confirm_adds_to_scope` (default on). Assets confirmed earlier are not
  backfilled.
- Upgrade note: migration `scope_origin_confirmed_asset` widens the origin
  check on `scope_targets`. It is safe on populated tables.
