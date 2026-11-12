### Added: web page monitoring (API)

- Watch URLs of the organization's web services: JS-only mode (default) keeps the scripts a page loads and, for each first-party script, its hash, size and the URLs found in it; full mode also keeps the page's masked visible text. Routes under `/api/v1/easm/page-monitoring` (watches, suggestions, changes with their diff); reads follow the data scope of the watch's web service, watch changes need `scans:write` and are audited.
- Fetch results arrive as the reserved report property `web_content` and are normalized and diffed on the platform (cache busters, build hashes, nonces and other volatile tokens ignored; per-watch ignore patterns); only a change is stored (last 5 snapshots per watch, changes kept 180 days).
- A new third-party script host on a watched page is a `third_party_script_added` exposure (high), announced through the attack surface alerts and resolved when the page drops the host.
- Fetches are dispatched every 10 minutes through the coverage path (scope and active-scan gates, signed jobs) for organizations with automatic coverage on; until a sensor can run the `monitor.web_content` capability, watches show as waiting.
- Migration 20261031064439 adds the `web_watches`, `web_snapshots` and `web_changes` tables and the exposure type.
