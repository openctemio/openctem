### Added: Discovery management for the attack surface

- Attack surface > Discovery shows the organization's coverage work in four stages (asset discovery, exposure scan, validation and scoping, technology discovery): status (idle, running, paused with its reason, failed), last run, progress, per-capability ledger counts, the daily budget and the number of assets in the last automatic attribution pass. Export as CSV.
- Run per stage and Run all make the stage's covered, due and failed coverage pairs due now; the coverage loop plans them on its next pass through the dispatch gate, within the daily budget. Paused, blocked and queued pairs are left alone. At most once a minute per stage (429 with `Retry-After`); refused while automatic coverage is off or the budget is spent (409).
- Abort all cancels the organization's active coverage runs through the run cancel; people's scans are not touched.
- `GET /api/v1/attack-surface/discovery` and `/export` need `scans:read`; `POST .../stages/{stage}/run` and `.../run` need `scans:write` and `scans:execute`; `POST .../cancel` needs `scans:write`. Every route needs access to all of the organization's assets (403 `DISCOVERY_FULL_DATA_REQUIRED` otherwise). Run and Abort are audited (`easm_discovery.run`, `easm_discovery.aborted`).
- No migration.
