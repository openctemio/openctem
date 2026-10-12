### Added: signed direct downloads, S3 server-side encryption, storage metrics and a local↔S3 copy command

- `STORAGE_DIRECT_DOWNLOAD=true` (off by default) adds
  `GET /api/v1/attachments/{id}/signed-url`: after the same checks as a
  download, a 60-second signed GET for that one object in an HTTPS bucket,
  forcing an attachment download. Local storage, plain-HTTP endpoints and
  flagged files answer `409` and download through the API. The console uses
  it for file downloads.
- `STORAGE_SSE` (`AES256` or `aws:kms`) and `STORAGE_SSE_KMS_KEY_ID` ask the
  server bucket to encrypt every object written.
- Metrics `openctem_storage_operations_total`,
  `openctem_storage_operation_seconds`, `openctem_storage_bytes_written_total`
  and `openctem_storage_events_total` (quota rejections, purges, scan
  results).
- `bootstrap-admin storage migrate -from local -to s3` (and the reverse) in
  the `admin-cli` image copies the server storage with the same keys,
  verifying each object by SHA-256; repeatable, `-dry-run`, `-tenant`,
  `-verify`. Switching `STORAGE_PROVIDER` without it leaves existing files
  unreachable (see `docs/architecture/file-storage.md`).
