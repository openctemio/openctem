### Fixed: technology detections removed from asset software

- A migration copies the technologies existing assets show into the asset technologies list; a
  background job (`asset-technology-backfill`, once per organization) gives them their category and
  removes the software component links earlier ingest created for detections that have no version and no
  CPE. A versioned or CPE-backed link is never removed, and each removed link is recorded. The first run
  only reports (a count and a sample in the log); set `ASSET_TECHNOLOGY_BACKFILL_REPORT_ONLY=false` to
  delete. Batches of 500 rows, no long locks (RFC-112).
- Upgrade note: migration `asset_technologies_backfill` reads `assets` and writes only the new tables.
