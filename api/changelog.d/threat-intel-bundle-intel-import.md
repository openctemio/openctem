### Added: KEV and EPSS from the signed vulnerability release

- The vulnerability bundle importer reads the release's signed KEV/EPSS side manifest (verified with the same pinned root and key set, bound to the applied release sequence) and applies each stream only when its data date is newer than the data the platform holds, from either path. A replayed or older copy never rolls the catalog back, a snapshot under 90 % of the stored count is refused, and KEV removals stay behind the existing prune guard. A stream that is not newer is not downloaded; a refused stream is recorded in that source's status and never undoes the corpus import. Unknown streams are skipped and listed.
- The sync status of KEV and EPSS records which path supplied the data (`delivered_via`), its data date (`intel_as_of`), and when the collector last read the source (`bundle_fetched_at`). The direct KEV and EPSS fetches keep running as before.
- The findings sweep, KEV reconciliation and event log that follow a KEV or EPSS sync are one shared function, run after a direct sync and after a bundle import.

### Fixed: the EPSS data date was the time of the fetch

- The EPSS file's `score_date` was never read (the metadata comment line was split at its comma and only the first half parsed), so every direct fetch dated its data with the fetch time. It now carries FIRST's real score date, which the no-rollback rule compares.
