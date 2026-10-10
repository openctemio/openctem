### Fixed: a report delivered late no longer undoes newer asset data

- Ingest uses the time a report's source saw the asset (the report timestamp, never later than now) instead of the arrival time: `last_seen` keeps the newer observation, and an older report's property values only fill gaps (RFC-069 §5.6).
- A delayed older port scan no longer closes a port a newer scan saw open.
- A stale asset that a scan reports again is saved active. Before, the asset history said "recovered" while the asset stayed stale.
