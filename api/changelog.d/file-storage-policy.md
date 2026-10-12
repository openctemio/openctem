### Security: file storage keeps an organization's files where it chose, with types from content and a quota

- An organization that stores its files in its own bucket no longer has them
  written to the server storage when that bucket cannot be used (rejected
  keys, blocked endpoint, unreadable setting): the upload fails with 503.
  A file recorded in the organization's bucket is read from there or not at
  all. Saving the storage setting applies to the next upload (it used to
  take up to 5 minutes).
- The type of an authorization letter is now taken from the file's content,
  like evidence attachments; the type the client declared was trusted before.
- New `STORAGE_TENANT_QUOTA_MB` (default 20480, 0 = none): an upload that
  would take an organization's attachments over it is refused with
  `413 STORAGE_QUOTA_EXCEEDED`.
- Uploading and deleting an evidence file is audited
  (`attachment.uploaded`, `attachment.deleted`) with its SHA-256.
- Attachments are streamed to the storage (hashed and counted on the way)
  instead of read into memory; the recorded size is the bytes received.
- Local storage writes each file atomically (temporary file, sync, rename)
  with directories `0700` and files `0600`. S3 storage accepts streamed
  bodies. Upgrade note: existing directories keep their mode.
- RFC-084 (file upload and storage) and `docs/architecture/file-storage.md`
  describe the storage, S3 setup and the bucket checklist.
