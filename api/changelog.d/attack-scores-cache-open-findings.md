### Fixed: attack-path scores are cached, skip deleted assets and count open findings only

- Attack-path scores are computed once per tenant per 5 minutes (concurrent requests share one run, under a 30 second deadline) instead of on every request.
- A relationship to a deleted asset no longer connects two assets in the scores, and no longer marks an asset as protected.
- The per-asset finding count that raises an asset's path score counts open findings only; resolved, closed and dispositioned findings no longer inflate it.
