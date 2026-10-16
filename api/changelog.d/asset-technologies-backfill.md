### Fixed: technology detections removed from asset software

- A migration copies the technologies existing assets show into the asset technologies list; a
  background job (`asset-technology-backfill`, once per organization) gives them their category and
  removes the software component links earlier ingest created for detections that are not versioned
  software (security headers such as HSTS, hosting platforms, CDNs, analytics tags, names without a
  version). Versioned products stay. Batches of 500 rows, no long locks (RFC-112).
- Upgrade note: migration `asset_technologies_backfill` reads `assets` and writes only the new tables.
