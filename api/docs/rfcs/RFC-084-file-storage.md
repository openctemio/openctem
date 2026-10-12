# RFC-084: File upload and storage

| | |
|---|---|
| Status | Implemented: P0 (#1900, #1901) and P1 (#1934, #1936, #1939, #1942), 2026-10-12; logo upload, asynchronous imports and exports later (§6) |
| Scope | api (`pkg/domain/attachment`, `internal/app/integration/attachment.go`, `internal/infra/storage`, upload routes and handlers, config), web (`/api/v1` proxy request bodies), deployment docs |
| Architecture | [file-storage.md](../architecture/file-storage.md) |
| Related | RFC-065 (authorization letters), RFC-076 (report templates), RFC-081 (web evidence screenshots), RFC-061 (content packs), finding-evidence.md, finding-import.md |

## 1. Summary

Files reach the platform for many reasons: pentest evidence, scan results to
import, SBOMs, authorization letters, report templates, screenshots taken by
sensors. One storage interface already holds most stored files
(`attachment.FileStorage`, drivers `local` and `s3`, per-tenant own bucket,
tenant erasure). This RFC makes every path use it consistently and safely:

- uploads are streamed, never buffered whole, and every import honours the
  limit it documents;
- the type of a stored file comes from its bytes, never from the client;
- an organization's files never silently leave the storage it chose;
- one organization cannot fill the shared storage (per-tenant quota);
- adding and removing evidence is audited with the file's SHA-256;
- the local driver writes atomically and privately;
- S3-compatible storage is documented for Docker and Kubernetes.

P1 (section 6) moves report files out of Postgres and adds retention for
orphaned evidence, image metadata stripping, optional malware scanning,
short-lived signed downloads, server-side encryption options, metrics and a
local↔S3 copy command. Asynchronous large imports and exports and logo
upload come later.

## 2. Inventory

| Path | Bytes | Limit | Notes |
|---|---|---|---|
| Evidence attachments `/api/v1/attachments` | FileStorage | 10 MiB/file | sniffed type, allow-list, campaign/finding/uploader authz |
| Manual finding evidence `/findings/{id}/evidence` | FileStorage | 10 MiB | finding data scope |
| Authorization letters `/scope/letters` | FileStorage | 10 MiB | PDF/PNG/JPEG; type now sniffed (was client-declared) |
| Web evidence screenshots | FileStorage (`StoreBlob`) | 10 MiB | re-encoded PNG; 30-day retention |
| Content packs (tenant, platform) | server FileStorage | pack limit | canonical tar, signed |
| Report templates (DOCX) | FileStorage (`StoreBlob`) | 10 MiB, 20/org | moved from Postgres `bytea` (§3.8) |
| Stored report artefacts | FileStorage (`StoreBlob`) | 50 MiB | moved from Postgres `bytea` (§3.8) |
| Scanner templates | Postgres `bytea` | 2 MiB | stays (small, versioned with the row) |
| Finding import `/findings/import` | not stored, streamed | 110 MiB | archives spooled to a temp dir |
| SBOM / asset CSV / campaign imports | not stored | 50 MiB | route limits now replace the global 10 MiB |
| VEX, API spec, credential CSV | not stored | 5–10 MiB | |
| Sensor results v2/v3 | Postgres `ingest_jobs.payload` (queue) | 16 MiB × 256 segments | blanked after processing |
| Avatars, logos | URLs only | | avatar host allow-list; logo upload later (§6) |

## 3. Design

### 3.1 One interface

`attachment.FileStorage` (`Upload`, `Download`, `Delete`, `EraseTenant`) stays
the only storage interface. Keys are `{namespace}/{uuid}_{sanitized name}`;
the namespace is a tenant id (or a fixed platform namespace for platform
content packs). Drivers:

- **local**: files under `STORAGE_LOCAL_PATH`. Each upload is written to a
  temporary file in the tenant directory, synced and renamed to its key, so a
  crash or a dropped upload never leaves a partial file under a key.
  Directories are `0700`, files `0600`. Suits one API replica, or several on a
  ReadWriteMany volume.
- **s3**: AWS S3, MinIO or any other service that speaks the S3 API, through
  `STORAGE_PROVIDER=s3|minio`, `STORAGE_BUCKET`, `STORAGE_REGION`,
  `STORAGE_ENDPOINT`, `STORAGE_ACCESS_KEY`, `STORAGE_SECRET_KEY`. A streamed
  body is spooled to a temporary file so the request can be signed over its
  payload; nothing is held in memory.

A namespace that is empty, a dot segment or contains a separator is refused
by both drivers.

### 3.2 Organization's own bucket

The Storage tab of organization settings lets an administrator (step-up,
audited High) keep files on the server storage or point them at the
organization's own S3-compatible bucket with its own keys, reached through
the SSRF-guarded client. This stays (data residency for organizations that
need it). It now **fails closed**: when the organization chose its own bucket
and that bucket cannot be built (bad keys, blocked endpoint, unreadable
setting), uploads fail with `503` instead of landing on the shared server
storage; a file recorded in the organization's bucket is read from there or
not at all. Saving the setting drops the cached provider, so it applies to
the next upload.

### 3.3 Uploads

- **Streaming.** The attachment service hashes (SHA-256) and counts the bytes
  while they go to the storage; the size limit holds on the bytes read, and
  the recorded size is the bytes read. A duplicate in the same context is
  detected after the write and its copy deleted.
- **Type from content.** `attachment.DetectContentType` decides the media
  type from the first 512 bytes; the file extension only refines generic text
  or binary (markdown, CSV, HAR, MP4/WebM) and never upgrades content to an
  active type. The allow-list has no HTML or SVG.
- **Effective limits.** Import routes declare their own body limit after the
  permission gate (finding import 110 MiB; SBOM, asset CSV and campaign
  import 50 MiB). The web console's `/api/v1` proxy streams those routes to
  the API instead of reading them into memory; other requests keep the 12 MiB
  in-memory cap. Multipart forms keep at most 1 MiB in memory.
- **Quota.** `STORAGE_TENANT_QUOTA_MB` (default 20480 = 20 GiB, 0 = none)
  bounds the bytes one organization's attachments hold. Checked on the
  declared size before the transfer and on the bytes read after it; an
  upload over it gets `413 STORAGE_QUOTA_EXCEEDED`.
- **Audit.** `attachment.uploaded` and `attachment.deleted` record the file
  name, type, size, SHA-256 and context.

### 3.4 Downloads

Downloads go through the API after the same authorization as today
(tenant-scoped lookup, campaign/finding/uploader checks). Every API response
carries `X-Content-Type-Options: nosniff` and
`Content-Security-Policy: default-src 'none'`; attachments other than raster
images are served `Content-Disposition: attachment`.

**Short-lived direct downloads** (`STORAGE_DIRECT_DOWNLOAD`, off by
default). `GET /api/v1/attachments/{id}/signed-url` runs the same checks
as the download (permission, tenant-scoped lookup, campaign/finding/uploader
rules) and returns `{url, expires_at}`: a GET signed by the storage driver
for that one object (`{tenant id}/{key}`, both from the row, never from the
request), valid 60 s, with `response-content-disposition: attachment` (the
file's name), `response-content-type` (its sniffed type) and
`response-cache-control: private, no-store` forced. The URL is bound to the
tenant, the object and the expiry by the signature; it is returned as JSON
(`Cache-Control: no-store`, `Referrer-Policy: no-referrer`), never as a
redirect, so the console's API proxy never fetches a bucket URL. Only an
HTTPS endpoint (or AWS S3) is signed; local storage, a plain-HTTP endpoint,
a flagged file (§3.7, always through the API with its confirmation) and the
feature turned off answer `409 DIRECT_DOWNLOAD_UNAVAILABLE` (or
`MALWARE_DETECTED`), and the caller downloads through the API. The console
uses it for file downloads (not for inline images, which stay same-origin,
so its CSP is unchanged); a bucket needs CORS only for clients that start
downloads with `fetch`.

### 3.5 Retention

Evidence follows its parent. A sweep (controller, hourly, one replica)
marks finding, retest and campaign attachments whose parent no longer exists
in the attachment's own organization, and purges them
`STORAGE_ORPHAN_GRACE_DAYS` (7) after the mark: the grace period covers a
deletion that is undone or a restore. Uploads never linked to a parent are
purged `STORAGE_UNLINKED_RETENTION_HOURS` (24) after upload. Each purge is
one tenant-scoped operation (storage resolved first, row deleted only if
still purgeable, then the file) and is audited `attachment.purged` in the
file's organization with the reason and SHA-256. Authorization letters and
other contexts are never purged.

### 3.6 Image hygiene

An uploaded PNG, JPEG, GIF or WebP is parsed before it is stored (images
are the one kind held in memory, bounded by the 10 MiB file limit):

- dimensions above 50 megapixels (any GIF frame included) are refused with
  `400 IMAGE_TOO_LARGE`, a damaged image with `400 IMAGE_INVALID`: a small
  file must not make a viewer or the report renderer allocate a huge bitmap;
- metadata is removed without re-encoding the pixels: JPEG APP1 (EXIF with
  GPS, XMP), APP13 (IPTC), other APPn and comments; PNG text chunks, eXIf
  and tIME; GIF comments, plain text and application extensions other than
  looping; WebP EXIF and XMP. What changes how the image looks stays
  (color profile, transparency, animation, and the JPEG orientation in a
  minimal EXIF segment of its own);
- the attachment's SHA-256 is the stored bytes; the upload audit event adds
  `original_sha256` (the bytes received) and `metadata_removed`.

### 3.7 Malware scanning

Optional, off by default: `STORAGE_CLAMD_ADDRESS` names a ClamAV daemon
(`host:port` or `unix:/path`); a Compose overlay and a Kubernetes manifest
ship as examples. With it set, a new upload starts `scan_status = pending`
and a worker (controller `attachment-malware-scan`, every 30 s, one replica)
streams it to clamd and records `clean`, `infected` (with the signature,
audited `attachment.malware_detected`, High) or `error` (clamd refused the
file). While clamd cannot be reached files stay pending.

For evidence a scan **marks, it never blocks**: exploit code and samples
are legitimate pentest evidence. A flagged file answers
`409 MALWARE_DETECTED` until the request confirms with `?confirm=malware`;
it then downloads as an attachment, never inline or cached, and the
download is audited `attachment.infected_downloaded` (High). Reports never
embed a flagged image, and the console shows flagged files apart with a
confirmation dialog. Files uploaded before a scanner was configured keep
an empty status (not scanned).

### 3.8 Report files out of Postgres

Report templates and stored reports go to the organization's file storage
(the same resolution as attachments: its own bucket if it chose one,
failing closed); the row keeps `storage_key`, `storage_provider` and
`size_bytes`. A read checks the file against the SHA-256 recorded for it
(the template's `content_sha256`, the report's `content_sha256`): a file
changed in the storage, for instance in an organization's own bucket, is
refused (`STORED_FILE_MISMATCH`). Existing rows are moved by the
`report-file-migration` job (every minute, one replica, 10 rows per kind
per run): each file is written, read back and compared before the row
switches to it and its bytes are cleared; a row that cannot be moved keeps
its bytes and keeps working. Migration `002063` is the expand step (nullable
`content`, new columns); a later release drops `content`.

A deleted row, directly or through a cascade (report, campaign,
organization), queues its file in `storage_blob_deletions` (a database
trigger, so no delete path can miss it); the retention sweep deletes queued
files from their organization's storage. Deleting the organization itself
queues nothing: its whole namespace is erased.

### 3.9 Server-side encryption, metrics, moving between drivers

- `STORAGE_SSE` (`AES256` or `aws:kms`) and `STORAGE_SSE_KMS_KEY_ID` ask the
  server bucket to encrypt every object written (`PutObject` headers);
  unset, the bucket's default encryption applies. An organization's own
  bucket uses its own default encryption.
- Metrics (no tenant or file in any label): `openctem_storage_operations_total`
  and `openctem_storage_operation_seconds` by operation and backend (server,
  organization), `openctem_storage_bytes_written_total`, and
  `openctem_storage_events_total` (quota rejections, purges by reason, scan
  results).
- `bootstrap-admin storage migrate -from local -to s3` (or the reverse; the
  `admin-cli` image) copies the server storage object by object under the
  same namespace and key, reads each copy back and compares its SHA-256,
  skips objects already copied (repeatable after an interruption; `-verify`
  also hashes those), never modifies the source and never follows symlinks.
  No database change is needed: rows record `local` for the server storage
  whatever its driver. `-tenant` limits it to one organization, `-dry-run`
  lists. Procedure: copy while the API runs, stop the API, copy again, switch
  `STORAGE_PROVIDER`, start.

## 4. Threat model

Assets: evidence (may hold secrets, personal data, exploit material),
letters, reports, organization storage keys. Actors: a member (malicious or
compromised), another organization, an internet attacker, an operator
mistake.

| Threat | Control |
|---|---|
| Path traversal, symlink escape | server-generated keys, sanitized names, namespace check, tenant dir resolved and kept under the base path, atomic temp file in the same dir |
| MIME confusion, stored XSS | type from content (letters included), allow-list without HTML/SVG, nosniff, `default-src 'none'`, attachment disposition |
| Cross-tenant object access | tenant-scoped row lookup, tenant key prefix, erasure refuses non-tenant namespaces; tested |
| Signed URL leak or reuse | issued only after the download checks, for one object, 60 s, attachment disposition forced, JSON with `no-store` and `no-referrer`, HTTPS endpoints only; never for flagged files |
| Copy tool writing outside a namespace or copying host files | namespace and key validated on both drivers, symlinks and temporary files skipped, every copy verified by SHA-256, source read-only |
| Residency bypass | own bucket fails closed (no fallback to shared storage) |
| DoS through uploads | streaming (proxy and API), effective per-route limits, per-tenant quota, rate limits on import routes |
| SSRF through a tenant bucket endpoint | SSRF-guarded client, endpoint validation |
| Zip/XML bombs in imports | importer archive limits (entries, size, ratio), strict parsers |
| Image decompression bombs | 50-megapixel limit on the declared dimensions (every GIF frame), checked before storing |
| Location and identity leaks in evidence images (EXIF GPS, XMP author) | metadata removed on upload, pixels untouched; original hash audited |
| Evidence tampering, repudiation | SHA-256 recorded; upload/delete audited |
| Report file swapped in the storage (organization bucket) | read checked against the recorded SHA-256; refused on mismatch |
| Files outliving their rows | delete trigger queues the file on every delete and cascade; retention sweep deletes it in its organization's storage |
| Bucket misconfiguration | documentation: block public access, TLS only, least-privilege key, server-side encryption |
| Evidence outliving its finding (secrets, personal data) | retention sweep purges it after the grace period, audited |
| Retention deleting the wrong files | parent looked up in the file's own organization only; finding, retest and campaign contexts only (letters never); row deleted only while still purgeable; storage resolved before the row goes |
| Malware distribution | files only reachable by authorized members, attachment disposition; optional clamd scan marks flagged files, which download only after a confirmation (audited) and are never embedded in reports |
| Hostile scanner input | clamd is operator configuration on the internal network; a scan reads the file from the row's own tenant storage; a result is recorded only on a pending row of that tenant |

## 5. Decisions

- Keep and extend the existing interface rather than add a second one.
- The per-organization bucket option stays and fails closed.
- Quota per organization from configuration now; per plan later.
- S3 credentials are static keys (no ambient credential chain) for both the
  server and organization buckets.

## 6. Phases

**P0** (implemented): effective import limits and streamed proxy (#1900);
content-sniffed types, streaming attachment upload, fail-closed own bucket,
quota, audit, atomic private local writes, S3 streaming, S3 documentation
(#1901).

**P1** (implemented): retention for evidence whose finding or campaign is
deleted and for uploads never linked (§3.5, #1934); image metadata stripping
and a pixel limit (§3.6), malware scanning with an optional ClamAV daemon,
marking, not blocking, evidence (§3.7, #1936); report templates and stored
reports moved from Postgres to the storage (§3.8, #1939); short-lived direct
downloads from a bucket (§3.4), S3 server-side encryption options, storage
metrics and the `local`↔`s3` copy command (§3.9, #1942).

**Later** (designed, not built): an uploaded organization logo instead of a
URL (closes the remote-image tracking of `logo_url`); asynchronous large
imports read from the storage (removes the request-time limit of the finding
import); asynchronous exports delivered with signed links; dropping
`pentest_report_templates.content` and `pentest_report_files.content` once
every deployment has moved them.

**P2**: resumable multipart uploads with presigned parts, direct-to-bucket
upload with a validating finalize step, envelope encryption for local
storage, keeping original SBOM documents, compliance control evidence, ticket
attachment sync.

## 7. Not built

A second storage abstraction or a generic blob table; a resumable upload
protocol before a file size needs it; deduplication across organizations
(an existence oracle); application-level encryption for local files; an
Azure Blob driver; blocking malware scans on pentest evidence.
