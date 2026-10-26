### Behaviour change: an asset goes stale on its last sighting only

- The lifecycle worker's clock is the asset's last sighting. It also read `updated_at`, which the table's trigger moves on every write, including risk rescores, the scoring version stamp and program links, so assets with open findings never went stale and a scoring version publish restarted the countdown for the whole organization. Expect a one-time batch of stale transitions on the first run after the upgrade (at most 50,000 per organization per run, as before). Reactivating an asset by hand still holds it active for the grace period, and a manual status still wins.

### Fixed: an inactive asset found again is not recorded as recovered

- Ingest revives a stale asset only. An inactive asset (a closed port, a person's decision) stays inactive; it used to get a "recovered" history entry while the stored row stayed inactive.
