### Fixed: dashboard widgets never draw a figure before there is something to count

- A scope with no finding yet shows every findings widget in one compact "No data yet" state with the next step (import results or set up a scan) instead of zeros, empty charts or a diagram of zeros; Priority exposure no longer reports its target as met when nothing has been measured. An empty widget takes one row of the dashboard.
- "KEV on your assets" shows how many open findings it is part of ("3 of 40 open").

### Added: discovery coverage says why assets are not covered

- The Discovery coverage widget splits the uncovered assets by cause: no eligible sensor, sensor or proxy failure, paused, target did not answer, never run, overdue, out of scope. Each cause opens the matching asset list (new asset list filter `coverage_cause`).
