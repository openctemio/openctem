### Fixed: a sensor back from an outage no longer gets the same scan's work twice

- An automatic retry no longer starts next to an active run of the same scan
  (a scheduled run or a coverage pass started after the failure): it is skipped,
  checked under the scan row lock like a scheduled occurrence, and written to the
  audit log ("Automatic retry skipped: the scan already has an active run"). A
  failed run is no longer retried once a newer run of the scan has started.
- A run that ends (settled, failed fast, failed to start) cancels the work no
  sensor has picked up yet in the same statement, with the reason on each
  command; a cancel and the deadline reapers already closed theirs.
- No claim path (poll, claim by id, batch claim, shared sensors) hands out a
  command whose run has ended, so leftovers of an earlier run (kept up to 48 h
  before) are never run next to the scan's next run. Another organization's
  commands are judged by their own organization's runs only.
- Coverage: a run that reached its deadline with every command refused by
  the sensor (its local policy, its egress) or never picked up now counts as
  a run no sensor took (a run that failed on its own stays a failure), so the capability backs off (paused `not_claimed` after 3 such runs,
  probe after 2 h doubling to 48 h, lifted at once when the sensors change)
  instead of queueing the same work again the moment the run timed out.
- No migration.
- **Upgrade note:** no action. After the upgrade, queued work of runs that already ended is no longer handed to sensors (it is cancelled when its run ends or by the reapers), and an automatic retry is skipped while its scan has an active run; each skip is in the audit log.
- Docs: server/docs/architecture/scan-lifecycle.md ("Cancel, deadline, retry"), server/docs/architecture/asset-coverage.md ("Runs no sensor takes"), https://docs.openctem.io/scanning/scans-and-runs/
