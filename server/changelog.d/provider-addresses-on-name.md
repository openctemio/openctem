### Behaviour change: provider addresses a name resolves to are recorded on the name

- An address inside a range a provider publishes for infrastructure many organizations share is recorded on the name that resolves to it (with first and last seen, per source), not as an address asset of the organization. Addresses a scan reports results on are still recorded, as the provider's. Unknown and dedicated addresses are unchanged.
- The asset list hides provider addresses by default behind a "Provider addresses (N)" filter, and they leave the inventory totals, the dashboard figures and the posture surface.
- A name's detail page shows its addresses grouped by provider ("Served by ...") with their history; `GET /api/v1/assets/{id}/addresses` returns them.
- Searching the inventory for an address finds the names that resolve or resolved to it.
- The ingest receipt counts these answers (`assets.recorded_on_name`); migrations `receipt_addresses_on_name` and `asset_set_elements_address_index` (built concurrently).
- Docs: server/docs/architecture/easm.md (section 4m2)
