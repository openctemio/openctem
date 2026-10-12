# File storage

Design and phases: [RFC-084](../rfcs/RFC-084-file-storage.md). Evidence
semantics: [finding-evidence.md](finding-evidence.md). Imports:
[finding-import.md](finding-import.md).

## What is stored where

| Kind | Where the bytes live |
|---|---|
| Evidence attachments, manual finding evidence, authorization letters, web evidence screenshots | file storage, namespace `{tenant id}/` |
| Content packs | server file storage (`{tenant id}/`, platform packs `platform-content/`) |
| Report templates, stored reports, scanner templates | Postgres rows (report bytes move to file storage in a later phase) |
| Imports (findings, SBOM, VEX, CSV) | not stored: parsed while streamed |

The **server file storage** is operator configuration (`STORAGE_*`). An
organization may instead point its files at **its own bucket** (Settings >
Organization > Storage, administrators, step-up, audited).

## Server storage: local volume (default)

`STORAGE_PROVIDER=local` writes under `STORAGE_LOCAL_PATH`
(`/app/data/attachments` in the image). Each file is written to a temporary
file, synced and renamed into place; directories are `0700` and files
`0600`, owned by the API's user.

- **Docker Compose**: the `api-data` volume is mounted at `/app/data`
  (`deploy/docker-compose.yml`). The root filesystem is read-only, so uploads
  fail without it. `deploy/backup.sh` archives the volume with the database.
- **Kubernetes (Helm)**: `api.attachments.storage: local` with
  `api.attachments.persistence` (a PVC at `/app/data`). More than one API
  replica needs a ReadWriteMany volume or S3; the chart refuses to render
  otherwise.

Back up the directory with the database: a database restored without its
files leaves attachments that answer 404.

## Server storage: S3-compatible bucket

AWS S3, MinIO or any other service that speaks the S3 API works.

```env
STORAGE_PROVIDER=s3          # minio: custom endpoint with path-style addressing
STORAGE_BUCKET=openctem-attachments
STORAGE_REGION=eu-west-1     # empty: us-east-1
STORAGE_ENDPOINT=            # empty for AWS S3; e.g. https://minio.internal:9000
STORAGE_ACCESS_KEY=...
STORAGE_SECRET_KEY=...
```

- **Docker Compose**: put these in `.env`; the `api-data` volume is then not
  used for new files.
- **Kubernetes (Helm)**: `api.attachments.storage: s3` and
  `api.attachments.s3.{provider,bucket,region,endpoint,existingSecret}`.
- Only static keys are used; nothing is read from the ambient AWS
  environment. The endpoint is operator configuration, so it may be a
  private address (an in-cluster store).

Bucket checklist:

- block all public access; deny requests without TLS;
- turn on default server-side encryption (SSE-S3 or SSE-KMS) and, if wanted,
  versioning with a lifecycle rule for old versions;
- give the key only what the API uses, on that bucket:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
     "Resource": "arn:aws:s3:::openctem-attachments/*"},
    {"Effect": "Allow", "Action": ["s3:ListBucket"],
     "Resource": "arn:aws:s3:::openctem-attachments"}
  ]
}
```

`s3:ListBucket` is used only to erase an organization's prefix when the
organization is deleted.

Switching `STORAGE_PROVIDER` does not move existing files: files keep the
provider recorded when they were uploaded.

## An organization's own bucket

An administrator can store the organization's files in its own S3-compatible
bucket with its own keys (encrypted at rest with `APP_ENCRYPTION_KEY`). The
endpoint goes through the SSRF guard (no loopback, link-local or, unless the
operator allows it, private addresses). When that bucket cannot be used
(keys rejected, endpoint blocked, setting unreadable) uploads fail with 503
rather than falling back to the server storage, and files recorded in the
bucket are served from it or not at all. Changing the setting applies to the
next upload. Deleting the organization erases its prefix in both the server
storage and its own bucket, and is refused while either cannot be erased.

## Limits and quota

| Upload | Limit |
|---|---|
| Evidence attachment, letter | 10 MiB per file |
| Finding import | 110 MiB per request (10 files) |
| SBOM, asset CSV, campaign Burp/CSV import | 50 MiB |
| Other request bodies | `SERVER_MAX_BODY_SIZE` (10 MiB) |

The web console streams the import routes to the API and keeps at most
12 MiB in memory for any other request. A reverse proxy in front must allow
the largest body (the bundled gateway allows 256 MB; an ingress needs e.g.
`nginx.ingress.kubernetes.io/proxy-body-size`).

`STORAGE_TENANT_QUOTA_MB` (default 20480, 0 = none) bounds what one
organization's attachments hold; an upload over it is refused with
`413 STORAGE_QUOTA_EXCEEDED`. Web evidence screenshots and content packs are
bounded by their own limits and retention, not by this quota.

## Upload checks

- The media type comes from the file's first bytes; the extension only
  refines generic text or binary. HTML and SVG are never accepted as files.
- Bytes are counted and hashed while they stream; the size limit and the
  quota hold on what was read.
- The same file (same SHA-256) uploaded twice to one finding returns the
  first attachment.
- Every API response has `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: default-src 'none'`; files other than raster
  images download as attachments.
- `attachment.uploaded` and `attachment.deleted` audit events record the
  file's name, type, size, SHA-256 and context.

## Shipped and planned

Shipped: local and S3 drivers, an organization's own bucket (fail closed),
tenant erasure, content-sniffed types, streamed uploads, the quota, upload
and delete audit, effective import limits with a streaming web proxy.

Planned (RFC-084 §6): short-lived signed downloads for S3; retention for
evidence whose finding or campaign is deleted and for uploads never linked;
report bytes moved out of Postgres; asynchronous large imports; image
metadata stripping; a malware scanning hook; S3 server-side encryption
options; a `local`↔`s3` migration command.

## Key files

- `pkg/domain/attachment/storage.go`: the `FileStorage` interface, the
  organization storage setting, limits and the allow-list.
- `pkg/domain/attachment/sniff.go`: `DetectContentType`.
- `internal/app/integration/attachment.go`: upload (stream, hash, quota,
  dedup), storage resolution per organization, erasure.
- `internal/infra/storage/local.go`, `s3.go`, `tenant.go`: drivers and the
  organization bucket factory.
- `internal/infra/http/handler/attachment_handler.go`,
  `scope_letter_handler.go`: upload, download, storage setting.
- `web/src/lib/api/proxy-upload.ts`: request body limits of the console's
  API proxy.
