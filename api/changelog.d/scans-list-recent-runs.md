### Changed: scan list shows recent runs, a fair success rate and why a run was blocked

- `GET /scans` items carry `recent_runs`: the scan's latest ten runs (id, status, refusal code, created time), newest first, read in one tenant-scoped query per page.
- The success rate counts a partial run (finished with coverage gaps) as a success and only failed or timed-out runs against it; blocked, canceled and live runs are not counted, and there is no rate below three counted runs. The list shows it over the latest ten runs next to their status glyphs, with the breakdown in the tooltip; the scan page and drawer use the same rule on the lifetime counters.
- A blocked latest run says why on the list, with a link to fix it (scope, exclusions, sensors, scan windows, scanners). A blocked run is drawn as a pause ring instead of the failure glyph: nothing ran.
- On a phone each scan is a compact card with no overlapping text; the intensity chip could previously overflow onto the next column. Intensity uses the neutral label system (plain tag, or a signal chip for intrusive) instead of coloured badges. The list's column titles and empty states are translated (en, vi).
