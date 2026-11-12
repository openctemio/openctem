### Added: Cloudflare R2 works as an S3-compatible storage target

- For any custom `STORAGE_ENDPOINT` (and a tenant's own bucket endpoint) the S3 driver now computes request checksums and validates responses only where an operation requires them. The SDK default trailing checksum is rejected by R2 and other S3-compatible stores; AWS S3 keeps the defaults.
- `STORAGE_SSE` and `STORAGE_SSE_KMS_KEY_ID` are refused at start-up when the endpoint is a Cloudflare R2 endpoint (R2 always encrypts at rest).
- New "Cloudflare R2" section in the file storage architecture doc: endpoints, bucket-scoped token, bucket lock for `audit-archive/`, location and jurisdictions.
