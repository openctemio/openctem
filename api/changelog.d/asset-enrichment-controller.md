### Added: automatic passive enrichment of new assets

- A new asset from any source (scans, sensor reports, imports, connectors,
  program targets, certificate transparency, manual create, CSV import) is
  enriched passively within minutes: root domains get DNS and registration
  (RDAP), host names DNS, addresses their network owner (ASN). Runs are
  ordinary passive scan runs of three built-in profiles, tagged
  `auto-enrichment`, through the usual dispatch gate: names no scope entry
  covers, internal targets and rejected names are dropped; nothing is sent
  to the target hosts (migrations `001981_asset_enrichment_requests`,
  `001982_asset_enrichment_profiles`, RFC-075).
- One request per asset (debounced 60 s, batches of at most 500, 6 h
  cooldown), at most `ASSET_ENRICHMENT_DAILY_BUDGET` (default 2 000) assets
  per organization per day. `ASSET_ENRICHMENT_ENABLED=false` turns it off
  for the platform.
- `GET/PUT /api/v1/easm/settings` gains `enrichment_enabled` (default on; a
  PUT without the field keeps the stored value) and `enrichment_available`.
  `GET /api/v1/assets/{id}/freshness` includes the asset's last enrichment.
