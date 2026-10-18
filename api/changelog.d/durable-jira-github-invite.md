### Fixed: ticket status sync and invitation e-mails survive a Redis outage

- The push of a finding's new status to its linked Jira or GitHub issue, and the invitation e-mail,
  were only queued in Redis: a Redis outage or restart, or a failed enqueue (only logged), lost them.
  They are now durable jobs: a row in the new `durable_jobs` table written in the same transaction as
  the status change, the invitation, or the resend, and run by the `durable-jobs` controller on any
  replica with retry and backoff. Jobs given up after eight attempts (or on a permanent error) stay
  in the table as `dead` with their last error, and are logged.
- The invitation link token in a queued e-mail is sealed with the application encryption key and
  removed once the e-mail is sent or given up.
- Migration `002933_durable_jobs` (new, empty table).
- **Upgrade note:** status pushes and invitation e-mails still waiting in Redis when the previous
  version stops are not sent; the next status change pushes the current status, and an invitation
  can be resent.
