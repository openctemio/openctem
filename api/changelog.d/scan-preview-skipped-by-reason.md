### Behaviour change: active scans of a wildcard or asset group take only names known to resolve

- A single-scanner active scan (nuclei, httpx, port scans) of `*.example.com` or of an asset group now leaves out the names the platform has never seen resolving, as it already did for names whose last DNS answer is over a week old. They are listed as skipped (`not_resolving`), not as failures; the asset's DNS coverage keeps checking them. Typed names and passive tools are unchanged.
- The scan's target options gain `include_unresolved` to hand those names to the sensor anyway.

### Added: skipped targets grouped by reason in the routing preview and the run

- `POST /scan-zones/preview` returns `will_scan`, `skipped_total` and `skipped` (one group per reason with a count, a tone and up to 200 names) and a `kind` on each skipped target. It accepts `target_options`, applies the resolve-before-active rule like the trigger, and runs in the caller's act scope.
- A run records the same groups in its context (`skipped_targets`, up to 25 names per reason); `GET /scan-runs/{id}` returns them in `dispatch.skipped` with `dispatch.will_scan`.

### Security: the routing preview no longer counts names outside the caller's data scope

- The preview resolved dynamic selectors without hiding the inventory names the caller may not act on, so its "skipped: outside the data scope" warning revealed how many such names exist. It now drops them before counting, as the Quick Scan preview does.
