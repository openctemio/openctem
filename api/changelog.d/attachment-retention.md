### Added: evidence files of deleted findings and never-linked uploads are purged

- A new `attachment-retention` controller (hourly, one replica at a time)
  marks evidence whose finding or campaign was deleted and, after
  `STORAGE_ORPHAN_GRACE_DAYS` (default 7), deletes the file and its row.
  Uploads never linked to a finding or campaign go after
  `STORAGE_UNLINKED_RETENTION_HOURS` (default 24). 0 keeps that class.
- Every purge is audited in the file's own organization
  (`attachment.purged`, with the reason and the file's SHA-256).
- A parent only counts in the file's own organization; authorization letter
  files, and any context other than finding, retest and campaign evidence,
  are never purged. A file whose organization bucket cannot be reached keeps
  its row and is retried.
- Migration `002060_attachment_retention` adds `attachments.orphaned_at` and
  two partial indexes (additive).
- **Upgrade note:** files that already belong to deleted findings or
  campaigns are purged 7 days after the first sweep; uploads older than 24
  hours that were never linked are purged on the first sweep. Set the two
  variables to 0 before upgrading to keep them.
