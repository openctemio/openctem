### Fixed: scan detail page and the New scan dialog

- The scan page refreshes its counters and status when a live run finishes, loads the first page of runs once, keeps the run history page and size in the URL, tells a missing scan from a failed load (with Retry), and no longer repeats the breadcrumb as a back link. Its text is translated (en, vi).
- The New scan dialog turns off "Run immediately" for a user without `scans:execute` and saves the scan without running it, and "View scan" opens the scan without a full page reload.
