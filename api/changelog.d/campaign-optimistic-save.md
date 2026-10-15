### Fixed: remediation campaign saves no longer undo each other

- Saving a campaign checks its `version`: a save made on a stale copy (a second tab, or the progress reconciler after someone paused or canceled the campaign) is refused with `409 Conflict` instead of silently reverting the change. `PATCH /api/v1/remediation/campaigns/{id}` and `/{id}/status` accept the `version` the caller edited; responses carry it.
- Reading a campaign (`GET`) never writes it any more; the reconciler and `POST /{id}/refresh` store the counts, through an update that never touches status.
- Completing a campaign of 1,000 or more findings no longer fails: the risk fields stored finding counts in `numeric(5,2)` columns. They are widened and left unset until campaign risk is measured; the counts they held are cleared (migration `remediation_campaign_version`).
- The reconciler no longer starves campaigns beyond its batch: it takes the least recently reconciled first and stamps each one it visits.
- A campaign is overdue only after the end of its due day (UTC), not from its first minute.
- Priority must be `critical`, `high`, `medium` or `low` (API validation and a database CHECK); stored `urgent` values become `critical`. An empty name is refused on update.
