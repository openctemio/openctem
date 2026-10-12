### Removed: unused background-job notification tasks

- The job worker no longer registers the `notification:process`,
  `notification:cleanup` and `notification:unlock_stale` task handlers or
  polls the `notifications` and `maintenance` queues. Nothing enqueued
  those tasks: notifications are delivered by the transactional outbox and its
  scheduler, which also cleans up and unlocks stale outbox entries. No
  behaviour changes.
