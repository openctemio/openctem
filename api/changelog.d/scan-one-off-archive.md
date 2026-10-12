### Fixed: one-off quick scans no longer clutter the scan list

- Quick scans created before quick scans became ad hoc (RFC-046 D10) were stored as ordinary configurations named "Quick Scan - YYYYMMDD-...", so they kept showing in the scan list. Migration 001154 marks them ad hoc: the default list hides them like every later quick scan, and "Save as scan" restores one as a configuration. Only manual scans that still carry both the generated name and the generated description are matched.

### Added: never-run one-off scans are archived after 30 days

- A new job (`one-off-scan-archive`, every 6 hours, one replica) archives ad-hoc scans that never had a run and are older than 30 days. An archived scan is disabled, left out of every scan list (also with one-off scans shown), and kept with its runs and audit trail; it is never deleted. Each archive is audited in the scan's tenant (`scan_config.disabled`, metadata `archived: true`).
- Migration 001154 adds `scans.archived_at`.
