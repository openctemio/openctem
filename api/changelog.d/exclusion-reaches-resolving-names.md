### Security: an exclusion of a dedicated address now stops the names resolving to it on every dispatch path

- The coverage batch, the workflow hop (names, asset ids and named open ports) and the claim-time recheck handed the gate bare names, so an out-of-scope dedicated address did not stop a name that resolves to it, contradicting the documentation and the bulk preview. The dispatch gate itself now reads the tenant's resolution relations (and what a probe of an asset id reaches) before matching exclusions, so every path behaves the same. The lookups are batched and tenant-scoped; a failed lookup stops the dispatch.
- Shared CDN and edge addresses still do not propagate to the names behind them.
