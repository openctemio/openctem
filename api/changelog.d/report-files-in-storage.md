### Changed: report templates and stored reports move from Postgres to the file storage

- New pentest report templates and stored reports are written to the
  organization's file storage (server storage or its own bucket, failing
  closed); the rows keep the key. Reads are checked against the recorded
  SHA-256 and refused when the file was changed.
- The `report-file-migration` controller moves existing rows (10 per kind
  per minute): each file is written, read back and compared, then the row's
  bytes are cleared. The database and its dumps shrink accordingly.
- Deleting a template or report, directly or with its campaign, removes
  its file (organization deletion erases the whole namespace): a trigger queues it in
  `storage_blob_deletions` and the attachment-retention sweep deletes it.
- Migration `002062_report_files_in_storage` (expand step): `content`
  becomes nullable, `storage_key`, `storage_provider`, `size_bytes` added
  (backfilled), the queue table and trigger. Its down refuses while any file
  lives only in the storage.
- **Upgrade note:** back up the file storage (the `api-data` volume or the
  bucket) together with the database from this release on: report files are
  no longer in the database dump once moved.
