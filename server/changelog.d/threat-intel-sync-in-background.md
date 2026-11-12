### Changed: "Sync now" runs in the background

- `POST /api/v1/admin/threat-intel/sync` queues the sync and answers 202 at once with a result per feed (`queued`, `already_running` or `skipped` with `disabled`, `not_configured` or `rate_limited`). Before, the download ran on the request, under the 30 second request timeout, and could be cut off or overlap the scheduled run. A feed that is switched off or has no bundle root key is not started (409 for a single feed); a feed started less than 15 seconds ago answers 429 with `Retry-After`.
- A feed runs once at a time: the scheduled run and an operator's request claim the feed's status row with one conditional update, across replicas. A run left `running` for more than an hour counts as interrupted and can be claimed again.
- The background job runs the whole controller pass (fetch, priority recompute for the findings whose CVE intel moved, KEV flag reconciliation, vulnerability events).
- Console: the card shows Running while a feed runs, the page refreshes every 2 seconds meanwhile, and a toast reports the real outcome of each requested sync.
