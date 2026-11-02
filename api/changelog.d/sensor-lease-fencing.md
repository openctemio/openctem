### Fixed: late results of an older run are fenced, and a failed delivery hands the claim back

- An organization sensor's results are now fenced by the lease epoch, as a
  shared sensor's already were: a stated old epoch is refused
  (`command-not-found`), and the ingest worker drops a queued report when its
  command was taken back and handed out again (to another sensor, or to the
  same one as a new run) after the report was accepted. Migration
  `ingest_reports_command_lease_epoch` adds a nullable column (no backfill,
  no lock beyond a catalog change).
- When a claim fails after the commands were claimed (the organization's
  HTTP policy, program rules or tool settings cannot be read, or the claimed
  rows cannot be read back), every claimed command is handed back at once.
  Before, the commands waited for their lease to expire, which counted an
  attempt, recorded the sensor as offline and excluded a healthy sensor.
