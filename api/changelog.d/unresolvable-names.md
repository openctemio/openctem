### Fixed: names that no longer resolve are skipped, not failed or dispatched

- A scan task whose every target is a name that does not resolve now completes with per-target skips (reason `target_unresolvable`) instead of failing; the run shows "N names no longer resolve" as information. Older sensors that report it as a failed command are handled too.
- Active stages no longer take names the platform knows do not resolve (new per-name resolution state, migration 003512). Passive stages keep them, so a name comes back by itself when it resolves again.
- Names that do not resolve at all are no longer marked wildcard-only: a name the filtered resolver left out is checked against DNS, and only a name that resolves through a probed wildcard record of its parent zone is marked. The migration clears the existing wildcard-only marks (they held no proof); the next resolve run marks again only the real ones.

### Added: resolution state of host names in the console

- Assets list filter `resolution=not_resolving`; the asset detail shows when the name last resolved (`resolution` in `GET /assets/{id}/freshness`); the run page has a "No longer resolve" skip group.
- **Upgrade note:** migration 003512 is a new table and clears `asset_wildcard_dns`; the platform needs DNS egress from the API host for the checks (the scan-zone resolver).
