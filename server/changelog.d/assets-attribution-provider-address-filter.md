### Fixed: asset lists accept the provider addresses filter

- `GET /assets` (and every list on the same filter registry) now accepts `attribution=provider_address`. It lists a provider's shared addresses. Before, the API refused the value with 400 "1 filter error", so the Needs attention queues "Decide monitoring" and "Validate primary", the inventory's "Show all" and its "Provider addresses" chip never loaded.
- `attribution=approved` and `attribution=attributed` (the default inventory) leave provider addresses out, as the inventory totals already did. `dependency` and `all` keep them.
- Docs: server/docs/architecture/easm.md (provider shared addresses: `attribution=provider_address` lists them)
