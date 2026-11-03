### Changed: finding identity uses CTIS fingerprint recipe v2; stored findings are re-keyed in place

- Ingest keys every finding kind with the CTIS fingerprint recipe v2 (`ctis-fp/2`) bound to its asset (identity version 3). Compliance, smart-contract and rule-only findings now have a recipe of their own; a finding's title is never part of its identity.
- Stored findings move to their new key in place: same finding id, triage, tickets and history; the old key stays an alias, so a late report in the old scheme lands on the same finding. Two stored findings that turn out to be one are merged through the finding merge (the earliest survives, nothing is deleted). CI run sightings follow the key.
- Secret findings stay keyed by the per-tenant keyed HMAC of the secret; no unsalted hash is ever used.
- **Upgrade note:** the API re-keys stored findings on start (one replica at a time, scan auto-resolve paused per organization while it runs; each organization changed gets a `findings.refingerprinted` audit entry). No manual step. To roll back to an earlier release, stop the API and run `refingerprint -down -apply` with this release's image first.
