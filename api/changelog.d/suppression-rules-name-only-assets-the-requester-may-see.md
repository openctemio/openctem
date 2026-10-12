### Security: suppression rules name only assets the requester may see

- Creating an asset-bound suppression rule (which auto-closes that asset's
  findings) now requires a live asset of the organization that the requester
  may see; anything else answers 404 `Asset`. `suppression_rules.asset_id`
  references `assets(id)` without the tenant, so a rule could name another
  tenant's asset or an out-of-scope one (research 21b M-10, RFC-050 W8).
- Docs: the authorization matrix and `api/CLAUDE.md` no longer say expiring
  grants will never be built (owner decisions D4/A2 reversed that; RFC-050
  W22/W23), and the tenant-wide aggregates table is marked as debt to scope
  (D6), not a decision (RFC-050 W10).
