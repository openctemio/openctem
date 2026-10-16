# File storage

Design and phases: [RFC-084](../rfcs/RFC-084-file-storage.md). Evidence
semantics: [finding-evidence.md](finding-evidence.md). Imports:
[finding-import.md](finding-import.md).

## What is stored where

| Kind | Where the bytes live |
|---|---|
| Evidence attachments, manual finding evidence, authorization letters, web evidence screenshots | file storage, namespace `{tenant id}/` |
| Report templates, stored reports | file storage, namespace `{tenant id}/` (rows written before moved by the `report-file-migration` job) |
| Content packs | server file storage (`{tenant id}/`, platform packs `platform-content/`) |
| Scanner templates | Postgres rows (small, versioned with the row) |
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

Server-side encryption per object: `STORAGE_SSE=AES256` (keys managed by
the store) or `STORAGE_SSE=aws:kms` with an optional
`STORAGE_SSE_KMS_KEY_ID` (the key needs `kms:GenerateDataKey` and
`kms:Decrypt` for the API's key). Unset, the bucket's default encryption
applies.

### Moving between local and S3

Rows record `local` for the server storage whatever its driver, so switching
`STORAGE_PROVIDER` alone makes existing files answer 404. Copy them first
with the `admin-cli` image (its `bootstrap-admin` binary), with the same
`STORAGE_BUCKET`/`_REGION`/`_ENDPOINT`/`_ACCESS_KEY`/`_SECRET_KEY` (and
`STORAGE_SSE`) the API will use:

```sh
# 1. what would be copied
bootstrap-admin storage migrate -from local -to s3 -local-path /app/data/attachments -dry-run
# 2. copy while the API runs (repeatable: copied objects are skipped)
bootstrap-admin storage migrate -from local -to s3 -local-path /app/data/attachments
# 3. stop the API, copy once more, set STORAGE_PROVIDER=s3, start the API
```

Docker Compose: run it in a one-off container of the `admin-cli` image with
the `api-data` volume mounted at `/app/data` and the `STORAGE_*` variables.
Each object keeps its namespace and key, is read back and compared by
SHA-256, and the source is never changed; `-verify` also hashes objects
already at the destination, `-tenant <id>` copies one organization. The
reverse (`-from s3 -to local`) works the same way. Organizations' own
buckets are not touched.

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

## Direct downloads

With `STORAGE_DIRECT_DOWNLOAD=true`,
`GET /api/v1/attachments/{id}/signed-url` returns `{url, expires_at}`
after the same checks as a download: a 60-second GET signed for that one
object, forcing `Content-Disposition: attachment`, the file's sniffed type
and `no-store`. It is JSON, never a redirect (the console's proxy never
fetches a bucket). Files on local storage, in a bucket without HTTPS and
flagged files answer `409 DIRECT_DOWNLOAD_UNAVAILABLE` / `MALWARE_DETECTED`;
the console then downloads through the API. The console uses it for file
downloads only; inline images stay same-origin. A bucket needs CORS only
for clients that start downloads with `fetch`.

## Metrics

On `/metrics` (no organization or file in any label):

| Metric | Labels |
|---|---|
| `openctem_storage_operations_total` | `op` (upload, download, delete, erase, presign), `backend` (server, organization), `result` |
| `openctem_storage_operation_seconds` | `op`, `backend` |
| `openctem_storage_bytes_written_total` | `backend` |
| `openctem_storage_events_total` | `event`: quota_rejected, purged_parent_deleted, purged_never_linked, scan_clean, scan_infected, scan_error |

## Images

PNG, JPEG, GIF and WebP uploads are parsed before they are stored:

- more than 50 megapixels (or a GIF frame that large): `400 IMAGE_TOO_LARGE`;
  a damaged image: `400 IMAGE_INVALID`;
- metadata goes, pixels stay: JPEG EXIF/XMP/IPTC/comments (the orientation
  is kept), PNG text/eXIf/tIME chunks, GIF comments and non-looping
  application extensions, WebP EXIF/XMP;
- the attachment's SHA-256 is the stored file; `attachment.uploaded` adds
  `original_sha256` and `metadata_removed` when bytes were removed.

## Malware scanning

Off by default. Set `STORAGE_CLAMD_ADDRESS` to a ClamAV daemon:

- **Docker Compose**:
  `docker compose -f docker-compose.yml -f docker-compose.clamav.yml up -d`
  (`api/deploy/docker-compose.clamav.yml`: a `clamav` service on the
  internal network, signatures in the `clamav-db` volume, about 1.5 GB of
  memory, outbound HTTPS for signature updates).
- **Kubernetes**: apply `api/deploy/kubernetes/clamav.yaml` (Deployment,
  Service, a NetworkPolicy that admits only the API pods) and set
  `api.extraEnv: [{name: STORAGE_CLAMD_ADDRESS, value: openctem-clamav:3310}]`.

New uploads start `pending`; the `attachment-malware-scan` controller (every
30 s, one replica, 50 files per run) streams each to clamd and records
`clean`, `infected` (signature in `scan_result`, audited
`attachment.malware_detected`) or `error`. While clamd is down files stay
pending. The attachment list returns `scan_status` and `scan_result`.

A flagged file is kept (pentest evidence often is malware on purpose):
`GET /api/v1/attachments/{id}` answers `409 MALWARE_DETECTED` until the
request adds `?confirm=malware`, then serves it as an attachment with
`Cache-Control: no-store` and audits `attachment.infected_downloaded`.
Reports skip flagged images; the console lists flagged files apart and asks
before downloading. Files uploaded with no scanner keep an empty status.

## Report files

Pentest report templates and stored reports are written to the
organization's file storage like attachments; `pentest_report_templates` and
`pentest_report_files` keep `storage_key`, `storage_provider` and
`size_bytes`. Each read is checked against the recorded SHA-256 and refused
on mismatch.

After upgrading, the `report-file-migration` controller (every minute, one
replica) copies rows that still hold bytes to the storage, 10 per kind per
run, reads each copy back and compares it, then clears the row's `content`.
A row it cannot move keeps its bytes and an error is logged each run. When
`SELECT count(*) FROM pentest_report_files WHERE content IS NOT NULL` and the
same for `pentest_report_templates` are 0, the move is complete. Back up the
file storage with the database from then on.

Deleting a template or report (or the campaign or organization holding it)
queues its file in `storage_blob_deletions` through a database trigger; the
`attachment-retention` sweep deletes it. Deleting the organization queues
nothing (organization erasure removes the namespace).

## Retention

The `attachment-retention` controller runs hourly on one replica:

1. It marks (`attachments.orphaned_at`) finding, retest and campaign evidence
   whose finding or campaign no longer exists **in the file's own
   organization**, and clears the mark if the parent exists again. A
   context id that is not a UUID names no parent and counts as deleted.
2. It deletes, oldest first and at most 500 per run, evidence marked more
   than `STORAGE_ORPHAN_GRACE_DAYS` (default 7) ago, and uploads never linked
   to a finding or campaign older than `STORAGE_UNLINKED_RETENTION_HOURS`
   (default 24; the console links files uploaded while a finding is being
   written as soon as it is created). 0 keeps that class.

Each file is handled on its own, in its organization: the storage is
resolved first (a file in an organization bucket that cannot be reached
keeps its row and is retried), then the row is deleted only if it is still
purgeable (linked or parent back in the meantime: kept), then the file.
Every purge is audited `attachment.purged` in the file's organization with
the reason (`parent_deleted`, `never_linked`), name, size and SHA-256.
Authorization letter files and contexts other than finding, retest and
campaign are never purged. Web evidence screenshots keep their own 30-day
retention.

## Shipped and planned

Shipped: local and S3 drivers, an organization's own bucket (fail closed),
tenant erasure, content-sniffed types, streamed uploads, the quota, upload
and delete audit, effective import limits with a streaming web proxy,
retention of evidence whose parent was deleted and of never-linked uploads,
image metadata removal and a pixel limit, optional malware scanning with
ClamAV, report templates and stored reports in the file storage,
short-lived direct downloads, S3 server-side encryption options, storage
metrics and the `local`↔`s3` copy command.

Planned (RFC-084 §6): an uploaded organization logo; asynchronous large
imports read from the storage; asynchronous exports with signed links;
dropping the old `content` columns of the report tables.

## Key files

- `pkg/domain/attachment/storage.go`: the `FileStorage` interface, the
  organization storage setting, limits and the allow-list.
- `pkg/domain/attachment/sniff.go`: `DetectContentType`.
- `pkg/domain/attachment/image.go`: image metadata removal and pixel limit.
- `pkg/domain/attachment/scan.go`, `internal/infra/malware/clamd.go`,
  `internal/app/integration/attachment_hygiene.go`,
  `internal/infra/controller/attachment_scan.go`: malware scanning.
- `internal/app/integration/attachment.go`: upload (stream, hash, quota,
  dedup), storage resolution per organization, erasure.
- `internal/app/integration/attachment_retention.go`,
  `internal/infra/postgres/attachment_retention.go`,
  `internal/infra/controller/attachment_retention.go`: the retention sweep.
- `internal/app/integration/report_files.go`,
  `internal/infra/postgres/pentest_report_file_store.go`,
  `internal/infra/controller/report_file_migration.go`: report files in the
  storage, the move, the deletion queue.
- `internal/infra/storage/local.go`, `s3.go`, `tenant.go`: drivers and the
  organization bucket factory; `metrics.go`: metrics; `migrate.go` and
  `internal/tools/bootstrapadmin/storage_migrate.go`: the copy command.
- `internal/app/integration/attachment_direct.go`: signed direct downloads.
- `internal/infra/http/handler/attachment_handler.go`,
  `scope_letter_handler.go`: upload, download, storage setting.
- `web/src/lib/api/proxy-upload.ts`: request body limits of the console's
  API proxy.
