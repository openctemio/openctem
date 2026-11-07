### Added: web path discovery at Standard depth

- New capability `enumerate.web_paths@1` (tool `webguess`, T1, GET and HEAD only): the platform requests paths derived from the organization's own inventory (backup copies of observed files, older and next API versions, paths its other origins serve, declared API paths never seen) and records the answers that differ from the origin's not-found page.
- Planned by automatic coverage on web services an active scope entry names, at most one run per origin per 30 days unless its inventory changed, and as an optional `paths` step in the Standard recon, Web and Deep recon workflows (migration `20261105060450_easm_workflow_path_discovery_step`).
- On by default; turn it off with `path_discovery: false` in the scope settings (audited). Budgets: `PATH_DISCOVERY_REQUESTS_PER_ORIGIN` (default 300) and `PATH_DISCOVERY_DAILY_REQUESTS` (default 50000); origins over the daily budget are deferred, never marked covered.

### Security: strict scope and program rules for enumeration

- A path discovery job always carries a strict web scope: GET and HEAD, every path exclusion on its hosts denied unless its testing mode is allowed (`read_only` included), and a per-host request cap the sensor enforces (`max_requests_per_host`). The candidate list is filtered with the sensor's reading of paths.
- A bug bounty program that forbids `bruteforce` or `automated_scanning` now gets no enumeration job (any `enumerate.*` capability or brute force) on its targets: refused at trigger, blocked in coverage, failed at claim with `PROGRAM_FORBIDS_ENUMERATION`.
- New coverage gap reasons from path discovery; an origin is never marked covered on `edge_protected`, `throttled` or `budget`.

### Security: one gate for every path discovery caller

- The coverage planner, the workflow `paths` step and a scan someone starts share one gate: the switch, the daily request budget, an active scope entry naming the origin's host, the shared edge and program refusals, `edge_clear`, `inventory_changed` and a per-origin last-run ledger (`web_path_discovery_runs`), so the 300 requests per origin per 30 days hold across callers. The claim is made by the web job guard, and a retry of a task is refused the same way.
- A path discovery job requires `net.confined@1`; its request cap is the platform's (a larger request is signed at the per-origin budget), and origins of one run on the same host share that host's budget. A wordlist pack runs only on origins an active scope entry names.
- The derived list reads the organization's sibling path counts once per 10 minutes (new expression index on web origin names) and ignores paths path discovery itself guessed.
- New coverage gap reasons: `path_ran_recently`, `not_an_origin`, `host_budget`.

### Added: guessed backup, archive and dump files are verified

- A guessed backup, archive or dump file is checked with the sensor's own `openctem-backup-file-signature` template, requested by id; a finding comes only from its hit.

### Fixed: a path discovery job that does nothing no longer holds its origin for 30 days

- The ledger claim is made last by the web job guard, after the confined-sensor check and the scope build, and is all or nothing across a job's origins. A job refused after the claim, one the repository cannot store, and an origin the sensor reports as `no_candidates` (no request sent) give the claim back and restore the previous row (migration column `claim_command_id`, `prev_*` of `web_path_discovery_runs`).
- Discovery deny paths are built with the same rule as every other web job (decoded forms, a `*` segment cut for sensors before webpath 1.3.1).
- New coverage gap reason `no_candidates` (en and vi words in the run view).
- Path discovery limits apply to any job whose required capability words name `enumerate.web_paths`, not only to the discovery tool; a discovery job with no origin target is refused.
- The ledger release for a sensor-reported empty job needs the exact origin, a detail that shows no request was sent, and happens once per origin per 30 days.
- An IPv6 origin is matched to its scope entry as a whole address.
