### Fixed: Quick Scan accepts wildcard targets

- A Quick Scan of `*.example.com` (or an inventory-mode range) is no longer refused with "in the scanner settings is a pattern, not a host". The typed targets are stored as the scan's targets only, so each run expands them to the known in-scope assets like a saved scan; they are no longer copied into the scanner settings.

### Added: preview of a quick scan before it starts

- `POST /api/v1/scans/quick/preview` (`scans:write` and `scans:execute`) shows, per typed target, the known assets a wildcard or range covers, how many names the run would scan and how many it leaves out by reason, and a few sample names. It uses the run's own expansion and scope checks as the caller (tenant, data scope, exclusions, deny list, caps) and creates nothing. A wildcard with no known name carries an offer to run subdomain discovery on its apex.
- The Quick Scan dialog shows it under "Review selection", and words refused wildcards in user terms (English and Vietnamese).
