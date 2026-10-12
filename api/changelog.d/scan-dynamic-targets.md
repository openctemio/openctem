### Added: scans of `*.example.com` and CIDRs follow the inventory at every run

- A wildcard domain in a scan's targets is resolved at the start of every run to the apex and every domain or subdomain asset the inventory holds at or under it, so a scheduled scan also scans the names found since its last run (RFC-068). Subdomain discovery (subfinder) still takes the apex only.
- A CIDR target can be swept as before (default) or, with `target_options.cidr_mode = inventory`, replaced at each run by the address assets the inventory holds inside the range.
- `target_options` on `POST /scans` and `PUT /scans/{id}`: `cidr_mode`, `seen_within_days` (0–365), `include_stale`. Archived assets are never taken; stale ones only on request; at most 5 000 assets per selector, the most recently seen first.
- Every expanded target goes through the dispatch gate as the inventory asset it is (exclusions, ownership, act scope, tier, private ranges); a selector authorizes nothing.
- `GET /scan-runs/{id}` reports what each selector added (`dispatch.target_expansion`); `GET /assets?in_cidr=` lists the address assets inside ranges; metrics `scan_target_selector_expansions_total` and `scan_stage_targets_skipped_total`.
- Migration `001640_scan_target_options` adds `scans.target_options` (constant default, no rewrite).

### Behaviour change: a wildcard target no longer refuses an active scanner

- `*.example.com` with nuclei, httpx or another active tool used to be refused (`WILDCARD_TARGET`); it is now a selector. `WILDCARD_TARGET` now refuses a wildcard whose root is a public suffix, a shared provider apex or a denied name, and a pattern in an active tool's `scanner_config.targets`. A run whose selectors cannot be read from the inventory is refused with `TARGET_SELECTOR_UNAVAILABLE`.
