### Changed: the scan list shows each scan's real last run, and a schedule switch only where there is a schedule

- The Scans list's Status column (the configuration's Active/Paused flag, read as a run state) is replaced by **Last run**. It shows the latest run's real state (Running with its progress, Completed, Partial, Failed, Blocked with the reason on hover, or Never) and when it started. Clicking it opens the run. The scan page and the scan drawer show the same chip.
- The on/off switch moved to the **Schedule** column as "Schedule on/off" with the next run. Only scans with a schedule have it; manual scans have none. The scan page and drawer offer **Run now** on any enabled scan, paused or not, and "Schedule on/off" only for scheduled scans.
- The **Type** column shows what the scan runs: the workflow's name or the single check's tool, instead of "Single Scan" on every row. Results count blocked runs. The Runs tab can filter blocked runs, and a blocked run's drawer says why it was refused.
- A **Show one-off scans** filter lists the quick scans that are hidden by default.
- **New scan > Targets:** a wildcard pattern (`*.example.com`) given to an active scanner offers two fixes. One is "Discover subdomains of example.com", which switches to subfinder with the root as the seed. The other is "Scan the N known assets matching *.example.com".
