### Added: the asset coverage ledger

- New table `asset_coverage` (migration 002134): one row per asset,
  capability and vantage with its state (due, queued, covered, failed,
  blocked, paused, not applicable), last attempt and success, outcome,
  failure streak and next due time (RFC-093).
- It replaces two narrower tables: the DNS checks' state
  (`easm_dns_check_state`, rows move as `dns.dangling` / `dns.email`) and the
  connector rotation cursor (`scan_coverage_state`, rows move as
  `network_va.connector`). The DNS checks and the connector rotation read and
  write the ledger; a DNS check the resolver could not decide is a failed
  attempt, a name the check does not apply to is not applicable.
- **Upgrade note:** the migration copies the rows (checked by count) and
  drops the two old tables, so stop the API during the deploy. The down
  migration restores both tables from the ledger.
