### Added: web path discovery at Standard depth

- New capability `enumerate.web_paths@1` (tool `webguess`, T1, GET and HEAD only): the platform requests paths derived from the organization's own inventory (backup copies of observed files, older and next API versions, paths its other origins serve, declared API paths never seen) and records the answers that differ from the origin's not-found page.
- Planned by automatic coverage on web services an active scope entry names, at most one run per origin per 30 days unless its inventory changed, and as an optional `paths` step in the Standard recon, Web and Deep recon workflows (migration `20261105060450_easm_workflow_path_discovery_step`).
- On by default; turn it off with `path_discovery: false` in the scope settings (audited). Budgets: `PATH_DISCOVERY_REQUESTS_PER_ORIGIN` (default 300) and `PATH_DISCOVERY_DAILY_REQUESTS` (default 50000); origins over the daily budget are deferred, never marked covered.

### Security: strict scope and program rules for enumeration

- A path discovery job always carries a strict web scope: GET and HEAD, every path exclusion on its hosts denied unless its testing mode is allowed (`read_only` included), and a per-host request cap the sensor enforces (`max_requests_per_host`). The candidate list is filtered with the sensor's reading of paths.
- A bug bounty program that forbids `bruteforce` or `automated_scanning` now gets no enumeration job (any `enumerate.*` capability or brute force) on its targets: refused at trigger, blocked in coverage, failed at claim with `PROGRAM_FORBIDS_ENUMERATION`.
- New coverage gap reasons from path discovery; an origin is never marked covered on `edge_protected`, `throttled` or `budget`.
